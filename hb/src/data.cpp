/* 
 * Class to work with suspicious activity and log file data. Read further for
 * small details about how data file looks like.
 * 
 * First position means type of record, almost all data is in fixed position
 * left padded with space to fill specified len. As exception to fixed position
 * is file_path. If filename will change, old one will be marked for removal and
 * new one added to end of file. Delete replaces whole line with "r" right
 * padded with spaces until end of line. Daemon start checks for removed record
 * count, if it exceeds 100, data file is rewritten with latest data and lines
 * starting with "r" are not saved (to get rid of them eventually).
 * 
 * Data about suspicious activity from address:
 * d|addr|lastact|actscore|actcount|refcount|whitelisted|blacklisted
 * 
 * Log file bookmark to check for log rotation and for seekg to read only new
 * lines:
 * b|bookmark|size|file_path
 *
 * Marked for removal (any type of line), right padded with spaces according to
 * original length of line:
 * r
 * 
 * addr        - IPv4 address, len 39, current implementation for IPv4, but len
 *               for easier IPv6 implementation in future
 * lastact     - unix timestamp of last activity, len 20
 * actscore    - suspicious activity score, len 10
 * actcount    - suspicious activity count (pattern match count), len 10
 * refcount    - connection drop count, len 10
 * whitelisted - flag if this IP address is in whitelist (manual list) and
 *               should never be blocked (ignore all suspicious activity for
 *               this address), y/n, len 1
 * blacklisted - flag if this IP address is blacklisted (manual list) and must
 *               be blocked allways, y/n, len 1
 * bookmark    - bookmark with how far this file is already parsed, len 20
 * size        - size of file when it was last read, len 20
 * file_path   - full path to log file, variable len (limits.h/PATH_MAX is not
 *               reliable so no max len here)
 */

// Standard input/output stream library (cin, cout, cerr, clog, etc)
#include <iostream>
// Standard string library
#include <string>
// File stream library (ifstream)
#include <fstream>
// Parametric manipulators (setw, setfill)
#include <iomanip>
// RegEx
#include <regex>
// Unordered map
#include <unordered_map>
// Linux stat
namespace cstat{
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
}
// Util
#include "util.h"
// Config
#include "config.h"
// Header
#include "data.h"

// Hostblock namespace
using namespace hb;

/*
 * Constructor
 */
Data::Data(hb::Logger* log, hb::Config* config, hb::Iptables* iptables)
: log(log), config(config), iptables(iptables)
{

}

/*
 * Read data file and store results in this->suspiciousAddresses
 * Note, config should already be processed
 */
bool Data::loadData()
{
	this->log->info("Loading data from " + this->config->dataFilePath);

	// Open data file
	std::ifstream f(this->config->dataFilePath.c_str());
	if (f.is_open()) {
		std::string line;
		char recordType;
		std::string address;
		hb::SuspiciosAddressType data;
		std::pair<std::map<std::string, hb::SuspiciosAddressType>::iterator,bool> chk;
		bool duplicatesFound = false;
		unsigned long long int bookmark;
		unsigned long long int size;
		std::string logFilePath;
		bool logFileFound = false;
		std::vector<hb::LogGroup>::iterator itlg;
		std::vector<hb::LogFile>::iterator itlf;
		unsigned int removedRecords = 0;

		// Clear this->suspiciousAddresses
		this->suspiciousAddresses.clear();

		// Read data file line by line
		while (std::getline(f, line)) {

			// First position is record type
			recordType = line[0];

			if(recordType == 'd' && line.length() == 92){// Data about address (activity score, activity count, blacklisted, whitelisted, etc)
				// IP address
				address = hb::Util::ltrim(line.substr(1,39));
				// Timestamp of last activity
				data.lastActivity = std::strtoull(hb::Util::ltrim(line.substr(40,20)).c_str(), NULL, 10);
				// Total score of activity calculated at last activity
				data.activityScore = std::strtoul(hb::Util::ltrim(line.substr(60,10)).c_str(), NULL, 10);
				// Suspicious activity count
				data.activityCount = std::strtoul(hb::Util::ltrim(line.substr(70,10)).c_str(), NULL, 10);
				// Refused connection count
				data.refusedCount = std::strtoul(hb::Util::ltrim(line.substr(80,10)).c_str(), NULL, 10);
				// Whether IP address is in whitelist
				if (line[90] == 'y') data.whitelisted = true;
				else data.whitelisted = false;
				// Whether IP address in in blacklist
				if (line[91] == 'y') data.blacklisted = true;
				else data.blacklisted = false;

				// If IP address is in both, whitelist and blacklist, remove it from blacklist
				if (data.whitelisted == true && data.blacklisted == true) {
					this->log->warning("Address " + address + " is in whitelist and at the same time in blacklist! Removing address from blacklist...");
					data.blacklisted = false;
				}

				// When data is loaded from datafile we do not have yet info whether it has rule in iptables, this will be changed to true later if needed
				data.iptableRule = false;

				// Store in this->suspiciousAddresses
				chk = this->suspiciousAddresses.insert(std::pair<std::string, hb::SuspiciosAddressType>(address, data));
				if (chk.second == false) {
					this->log->warning("Address" + address + " is duplicated in data file, new datafile without duplicates will be created!");
					duplicatesFound = true;
				}

			} else if (recordType == 'b') {// Log file bookmarks
				// Bookmark
				bookmark = std::strtoull(hb::Util::ltrim(line.substr(1,20)).c_str(), NULL, 10);
				// Last known size to detect if log file has been rotated
				size = std::strtoull(hb::Util::ltrim(line.substr(21,20)).c_str(), NULL, 10);
				// Path to log file
				logFilePath = hb::Util::rtrim(hb::Util::ltrim(line.substr(41)));

				// Update info about log file
				logFileFound = false;
				for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
					for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
						if (itlf->path == logFilePath) {
							itlf->bookmark = bookmark;
							itlf->size = size;
							logFileFound = true;
							this->log->debug("Bookmark: " + std::to_string(bookmark) + " Size: " + std::to_string(size) + " Path: " + logFilePath);
							break;
						}
					}
					if (logFileFound) break;
				}

				// If log file is not found this->config
				if (!logFileFound) {
					this->log->warning("Bookmark information in datafile for log file " + logFilePath + " found, but file not present in configuration. Removing from datafile...");
					this->removeFile(logFilePath);
				}

			} else if (recordType == 'r') {
				removedRecords++;
			}
		}

		// Finished reading file, close it
		f.close();

		// If duplicates found, rename current data file to serve as backup and save new data file without duplicates
		if (duplicatesFound) {
			// New filename for data file
			std::time_t rtime;
			struct tm * itime;
			std::time(&rtime);
			itime = std::localtime(&rtime);
			std::string month = std::to_string(itime->tm_mon + 1);
			if(month.length() == 1) month = "0" + month;
			std::string day = std::to_string(itime->tm_mday);
			if(day.length() == 1) day = "0" + day;
			std::string hour = std::to_string(itime->tm_hour);
			if(hour.length() == 1) hour = "0" + hour;
			std::string minute = std::to_string(itime->tm_min);
			if(minute.length() == 1) minute = "0" + minute;
			std::string second = std::to_string(itime->tm_sec);
			if(second.length() == 1) second = "0" + second;
			std::string newDataFileName = this->config->dataFilePath + "_" + std::to_string(itime->tm_year + 1900) + month + day + hour + minute + second + ".bck";

			// Check if new filename doesn't exist (so that it is not overwritten)
			struct cstat::stat buffer;
			if (cstat::stat(newDataFileName.c_str(), &buffer) != 0) {
				if (std::rename(this->config->dataFilePath.c_str(), newDataFileName.c_str()) != 0) {
					this->log->error("Current data file contains duplicate entries and backup creation failed (file rename failure)!");
					return false;
				}
			} else{
				this->log->error("Current data file contains duplicate entries and backup creation failed (backup with same name already exists)!");
				return false;
			}
			// Save data without duplicates to data file (create new data file)
			if (this->saveData() == false) {
				this->log->error("Data file contains duplicate entries, successfully renamed data file, but failed to save new data file!");
				return false;
			}
			this->log->warning("Duplicate data found while reading data file! Old data file stored as " + newDataFileName + ", new data file without duplicates saved! Merge manually if needed.");
		} else if (removedRecords > 100) {// If more than 100 removed records detected in datafile
			// Save data without without removed records data file - small space saving
			if (this->saveData() == false) {
				this->log->error("Data file contains more than 100 removed records, tried saving data file without records that are marked for removal, but failed!");
				return false;
			}
		}

		// Data file processing finished
		this->log->info("Loaded " + std::to_string(this->suspiciousAddresses.size()) + " IP address record(s)");
	} else {
		this->log->warning("Unable to open datafile for reading!");
		if (this->saveData() == false) {
			this->log->error("Unable to create new empty data file!");
			return false;
		}
	}

	return true;
}

/*
 * Save this->suspiciousAddresses to data file, will replace if file already exists
 */
bool Data::saveData()
{
	this->log->info("Updating data in " + this->config->dataFilePath);

	// Open file
	std::ofstream f(this->config->dataFilePath.c_str());
	if (f.is_open()) {

		// Loop through all addresses
		std::map<std::string, SuspiciosAddressType>::iterator it;
		for (it = this->suspiciousAddresses.begin(); it!=this->suspiciousAddresses.end(); ++it) {
			f << 'd';
			f << std::right << std::setw(39) << it->first;// Address, left padded with spaces
			f << std::right << std::setw(20) << it->second.lastActivity;// Last activity, left padded with spaces
			f << std::right << std::setw(10) << it->second.activityScore;// Current activity score, left padded with spaces
			f << std::right << std::setw(10) << it->second.activityCount;// Total activity count, left padded with spaces
			f << std::right << std::setw(10) << it->second.refusedCount;// Total refused connection count, left padded with spaces
			if(it->second.whitelisted == true) f << 'y';
			else f << 'n';
			if(it->second.blacklisted == true) f << 'y';
			else f << 'n';
			// f << std::endl;// endl should flush buffer
			f << "\n";// \n should not flush buffer
		}

		// Loop all log files
		std::vector<hb::LogGroup>::iterator itlg;
		std::vector<hb::LogFile>::iterator itlf;
		for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
			for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
				f << 'b';
				f << std::right << std::setw(20) << itlf->bookmark;
				f << std::right << std::setw(20) << itlf->size;
				f << itlf->path;
				// f << std::endl;// endl should flush buffer
				f << "\n";// \n should not flush buffer
			}
		}

		// Close datafile
		f.close();
	} else {
		this->log->error("Unable to open datafile for writting!");
		return false;
	}
	return true;
}

/*
 * Compare data with iptables rules and update iptables rules if needed
 */
bool Data::checkIptables()
{
	this->log->info("Checking iptables rules...");
	std::map<unsigned int, std::string> rules = this->iptables->listRules("INPUT");
	try {
		// Regex to search for IP address
		std::regex ipSearchPattern("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");

		// Loop through current rules and mark suspcious addresses which have iptables rule
		std::map<unsigned int, std::string>::iterator rit;
		std::size_t checkStart = 0;
		std::size_t checkEnd = 0;
		std::map<std::string, SuspiciosAddressType>::iterator sait;
		std::smatch ipSearchResults;
		for(rit=rules.begin(); rit!=rules.end(); ++rit){
			// Looking at rules like -A INPUT -s X.X.X.X/32 -j DROP
			checkStart = rit->second.find("-A INPUT -s");
			checkEnd = rit->second.find("-j DROP");
			if(checkStart != std::string::npos && checkStart == 0 && checkEnd != std::string::npos){
				// Find address in rule
				if(std::regex_search(rit->second, ipSearchResults, ipSearchPattern)){
					if(ipSearchResults.size() == 1){
						// Search for address in map
						sait = this->suspiciousAddresses.find(ipSearchResults[0]);
						if(sait != this->suspiciousAddresses.end()){
							if(sait->second.iptableRule == false){
								sait->second.iptableRule = true;
							} else {
								this->log->warning("Found duplicate iptables rule for " + sait->first + ", consider:");
								this->log->warning("$ sudo iptables --list-rules INPUT | grep " + sait->first);
								this->log->warning("$ sudo iptables -D INPUT -s " + sait->first + " -j DROP");
							}
						} else {
							this->log->warning("Found iptables rule for " + ipSearchResults[0].str() + " but don't have any information about this address in datafile, please review manually.");
							this->log->warning("$ sudo iptables --list-rules INPUT | grep " + ipSearchResults[0].str());
						}
					}
				}
			}
		}

		// Loop through all suspicious address and add iptables rules that are missing
		bool createRule = false;
		bool removeRule = false;
		std::time_t currentRawTime;
		std::time(&currentRawTime);
		unsigned long long int currentTime = (unsigned long long int)currentRawTime;
		for (sait = this->suspiciousAddresses.begin(); sait!=this->suspiciousAddresses.end(); ++sait) {
			createRule = false;
			removeRule = false;
			if (!sait->second.iptableRule) {// If this address doesn't have rule then check if it needs one
				// Whitelisted addresses must not have rule
				if (sait->second.whitelisted) {
					continue;
				}

				// Blacklisted addresses must have rule
				if (sait->second.blacklisted) {
					createRule = true;
				}

				if (this->config->keepBlockedScoreMultiplier > 0) {
					// Score multiplier configured, recheck if score is enough to create rule
					if (sait->second.activityScore > 0
							&& sait->second.lastActivity + sait->second.activityScore > this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier
							&& currentTime < (sait->second.lastActivity + sait->second.activityScore) - (this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier)) {
						createRule = true;
					}
				} else {
					// Without multiplier rules are kept forever for cases where there is enough score
					if (sait->second.activityScore >= this->config->activityScoreToBlock) {
						createRule = true;
					}
				}
			} else {// If this address has rule then check if rule has expired or address is manually added to whitelist so rule should be removed
				// Blacklisted addresses must have rule
				if (sait->second.blacklisted == true) {
					continue;
				}

				// Whitelisted addresses must not have rule
				if (sait->second.whitelisted == true) {
					removeRule = true;
				}

				if (this->config->keepBlockedScoreMultiplier > 0) {
					// Score multiplier configured, recheck if score is no longer enough to keep this rule
					if (currentTime > sait->second.lastActivity + sait->second.activityScore) {
						removeRule = true;
					}
				} else {
					// Without multiplier rules are kept until core is manually reduced under activityScoreToBlock
					if (sait->second.activityScore < this->config->activityScoreToBlock) {
						removeRule = true;
					}
				}
			}
			if (createRule == true) {
				this->log->warning("Address " + sait->first + " is missing iptables rule, adding...");
				try {
					if (this->iptables->append("INPUT","-s " + sait->first + " -j DROP") == false) {
						this->log->error("Address " + sait->first + " is missing iptables rule and failed to append rule to chain!");
					} else {
						sait->second.iptableRule = true;
					}
				} catch (std::runtime_error& e) {
					std::string message = e.what();
					this->log->error(message);
					this->log->error("Address " + sait->first + " is missing iptables rule and failed to append rule to chain!");
				}
			}
			if (removeRule == true) {
				this->log->warning("Address " + sait->first + " no longer needs iptables rule, removing...");
				try {
					if (this->iptables->remove("INPUT","-s " + sait->first + " -j DROP") == false) {
						this->log->error("Address " + sait->first + " no longer needs iptables rule, but failed to remove rule from chain!");
					} else {
						sait->second.iptableRule = false;
					}
				} catch (std::runtime_error& e) {
					std::string message = e.what();
					this->log->error(message);
					this->log->error("Address " + sait->first + " no longer needs iptables rule, but failed to remove rule from chain!");
				}
			}
		}
	} catch (std::regex_error& e) {
		std::string message = e.what();
		this->log->error(message + ": " + std::to_string(e.code()));
		this->log->error(hb::Util::regexErrorCode2Text(e.code()));
	}
	return true;
}

/*
 * Add new record to datafile end based on this->suspiciousAddresses
 */
bool Data::addAddress(std::string address)
{
	this->log->debug("Adding record to " + this->config->dataFilePath + ", adding address " + address);
	std::ofstream f(this->config->dataFilePath.c_str(), std::ofstream::out | std::ofstream::app);
	if (f.is_open()) {
		// Write record to datafile end
		f << 'd';
		f << std::right << std::setw(39) << address;// Address, left padded with spaces
		f << std::right << std::setw(20) << this->suspiciousAddresses[address].lastActivity;// Last activity, left padded with spaces
		f << std::right << std::setw(10) << this->suspiciousAddresses[address].activityScore;// Current activity score, left padded with spaces
		f << std::right << std::setw(10) << this->suspiciousAddresses[address].activityCount;// Total activity count, left padded with spaces
		f << std::right << std::setw(10) << this->suspiciousAddresses[address].refusedCount;// Total refused connection count, left padded with spaces
		if(this->suspiciousAddresses[address].whitelisted == true) f << 'y';
		else f << 'n';
		if(this->suspiciousAddresses[address].blacklisted == true) f << 'y';
		else f << 'n';
		// f << std::endl;// endl should flush buffer
		f << "\n";// \n should not flush buffer

		// Close datafile
		f.close();
	} else {
		this->log->error("Unable to open datafile for writting!");
		return false;
	}

	return true;
}

/*
 * Update record in datafile based on this->suspiciousAddresses
 */
bool Data::updateAddress(std::string address)
{
	bool recordFound = false;
	char c;
	char fAddress[40];
	this->log->debug("Updating record in " + this->config->dataFilePath + ", updating address " + address);
	std::fstream f(this->config->dataFilePath.c_str(), std::fstream::in | std::fstream::out);
	if (f.is_open()) {
		while (f.get(c)) {
			// std::cout << "Record type: " << c << " tellg: " << std::to_string(f.tellg()) << std::endl;
			if (c == 'd') {// Data record, check if IP matches

				// Get address
				f.get(fAddress, 40);

				// If we have found address that we need to update
				if (hb::Util::ltrim(std::string(fAddress)) == address) {
					f << std::right << std::setw(20) << this->suspiciousAddresses[address].lastActivity;// Last activity, left padded with spaces
					f << std::right << std::setw(10) << this->suspiciousAddresses[address].activityScore;// Current activity score, left padded with spaces
					f << std::right << std::setw(10) << this->suspiciousAddresses[address].activityCount;// Total activity count, left padded with spaces
					f << std::right << std::setw(10) << this->suspiciousAddresses[address].refusedCount;// Total refused connection count, left padded with spaces
					if(this->suspiciousAddresses[address].whitelisted == true) f << 'y';
					else f << 'n';
					if(this->suspiciousAddresses[address].blacklisted == true) f << 'y';
					else f << 'n';
					// f << std::endl;// endl should flush buffer
					f << "\n";// \n should not flush buffer
					recordFound = true;

					// No need to continue reading file
					break;
				}
				// std::cout << "Address: " << hb::Util::ltrim(std::string(fAddress)) << " tellg: " << std::to_string(f.tellg()) << std::endl;
				f.seekg(53, f.cur);
			} else {// Other type of record (bookmark or removed record)
				// We can skip at min 41 pos
				f.seekg(41, f.cur);

				// Read until end of line
				while (f.get(c)) {
					if (c == '\n') {
						break;
					}
				}
			}
		}

		// Close data file
		f.close();
	} else {
		this->log->error("Unable to open datafile for update!");
		return false;
	}

	if (!recordFound) {
		this->log->error("Unable to update " + address + " in data file, record not found in data file!");
		// Maybe better write warning, backup existing datafile and create new one based on data in memory?
		return false;
	} else {
		return true;
	}
}

/*
 * Mark record for removal in datafile
 */
bool Data::removeAddress(std::string address)
{
	bool recordFound = false;
	char c;
	char fAddress[40];
	// std:string buffer;
	this->log->debug("Removing record from " + this->config->dataFilePath + ", removing address " + address);
	std::fstream f(this->config->dataFilePath.c_str(), std::fstream::in | std::fstream::out);
	if (f.is_open()) {
		while (f.get(c)) {
			// std::cout << "Record type: " << c << " tellg: " << std::to_string(f.tellg()) << std::endl;
			if (c == 'd') {// Data record, check if IP matches

				// Get address
				f.get(fAddress, 40);

				// If we have found address that we need to remove
				if (hb::Util::ltrim(std::string(fAddress)) == address) {
					f.seekg(-40, f.cur);
					f << 'r';
					recordFound = true;
					break;// No need to continue reading file
				}
				// std::cout << "Address: " << hb::Util::ltrim(std::string(fAddress)) << " tellg: " << std::to_string(f.tellg()) << std::endl;
				f.seekg(53, f.cur);
			} else {// Variable length record (bookmark or removed record)
				// We can skip at min 41 pos
				f.seekg(41, f.cur);

				// Read until end of line
				while (f.get(c)) {
					if (c == '\n') {
						break;
					}
				}
			}
		}

		// Close data file
		f.close();
	} else {
		this->log->error("Unable to open datafile for update!");
		return false;
	}

	if (!recordFound) {
		this->log->error("Tried removing address " + address + " from datafile, but record is not present in datafile!");
		// Maybe better write warning, backup existing datafile and create new one based on data in memory?
		return false;
	} else {
		return true;
	}
	return false;
}

/*
 * Add new log file bookmark record to datafile
 */
bool Data::addFile(std::string filePath)
{
	this->log->debug("Adding record to " + this->config->dataFilePath + ", adding log file " + filePath);

	// Open datafile
	std::ofstream f(this->config->dataFilePath.c_str(), std::ofstream::out | std::ofstream::app);
	if (f.is_open()) {
		// Find log file in config
		std::vector<hb::LogGroup>::iterator itlg;
		std::vector<hb::LogFile>::iterator itlf;
		bool logFileFound = false;
		for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
			for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
				if (itlf->path == filePath) {
					// Write record to datafile end
					f << 'b';
					f << std::right << std::setw(20) << itlf->bookmark;
					f << std::right << std::setw(20) << itlf->size;
					f << itlf->path;
					// f << std::endl;// endl should flush buffer
					f << "\n";// \n should not flush buffer
					logFileFound = true;
					break;
				}
			}
			if (logFileFound) break;
		}

		// Report error if log file not found in config
		if (!logFileFound) {
			this->log->error("Unable to add " + filePath + " to data file, log file not found in configuration!");
			return false;
		}

		// Close datafile
		f.close();
	} else {
		this->log->error("Unable to open datafile for writting!");
		return false;
	}

	return true;
}

/*
 * Update log file bookmark record in datafile
 */
bool Data::updateFile(std::string filePath)
{
	bool recordFound = false;
	bool logFileFound = false;
	char c;
	std::string fPath;
	int tmppos;// To temporarly store current position in file
	this->log->debug("Updating record in " + this->config->dataFilePath + ", updating log file " + filePath);
	std::fstream f(this->config->dataFilePath.c_str(), std::fstream::in | std::fstream::out);
	if (f.is_open()) {
		while (f.get(c)) {
			// std::cout << "Record type: " << c << " tellg: " << std::to_string(f.tellg()) << std::endl;
			if (c == 'd') {// Address record, skip to next one
				f.seekg(92, f.cur);
			} else if (c == 'b') {// Log file record, check if path matches needed one
				// Save current position, will need later if file path will match needed one
				tmppos = f.tellg();

				// Skip bookmark and size
				f.seekg(40, f.cur);
				std::getline(f, fPath);
				if (fPath == filePath) {
					// Go back to bookmark position
					f.seekg(tmppos, f.beg);

					// Find log file in config
					std::vector<hb::LogGroup>::iterator itlg;
					std::vector<hb::LogFile>::iterator itlf;
					for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
						for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
							if (itlf->path == filePath) {
								// Update bookmark and size in datafile
								f << std::right << std::setw(20) << itlf->bookmark;
								f << std::right << std::setw(20) << itlf->size;
								logFileFound = true;
								break;
							}
						}
						if (logFileFound) break;
					}
					recordFound = true;

					// No need to continue work with file
					break;
				}
			} else {// Variable length record (removed)
				// We can skip at min 41 pos
				f.seekg(41, f.cur);

				// Read until end of line
				while (f.get(c)) {
					if (c == '\n') {
						break;
					}
				}
			}
		}

		// Close file
		f.close();
	} else {
		this->log->error("Unable to open datafile for update!");
		return false;
	}

	if (!recordFound) {
		this->log->error("Unable to update " + filePath + " in data file, record not found in data file!");
		// Maybe better write warning, backup existing datafile and create new one based on data in memory?
		return false;
	} else if (!logFileFound) {
		this->log->error("Unable to update " + filePath + " in datafile, log file not found in configuration!");
		return false;
	} else {
		return true;
	}
}

/*
 * Mark log file bookmark record for removal in datafile
 */
bool Data::removeFile(std::string filePath)
{
	bool recordFound = false;
	char c;
	std::string fPath;
	int tmppos;// To temporarly store current position in file
	this->log->debug("Removing record from " + this->config->dataFilePath + ", removing log file " + filePath);
	std::fstream f(this->config->dataFilePath.c_str(), std::fstream::in | std::fstream::out);
	if (f.is_open()) {
		while (f.get(c)) {
			// std::cout << "Record type: " << c << " tellg: " << std::to_string(f.tellg()) << std::endl;
			if (c == 'd') {// Address record, skip to next one
				f.seekg(92, f.cur);
			} else if (c == 'b') {// Log file record, check if path matches needed one

				// Save current position, will need later if file path will match needed one
				tmppos = f.tellg();

				// Skip bookmark and size
				f.seekg(40, f.cur);
				std::getline(f, fPath);
				if (fPath == filePath) {
					// Go back to record type position
					f.seekg(tmppos-1, f.beg);
					f << 'r';
					recordFound = true;

					// No need to continue work with file
					break;
				}
			} else {// Variable length record (removed)
				// We can skip at min 41 pos
				f.seekg(41, f.cur);

				// Read until end of line
				while (f.get(c)) {
					if (c == '\n') {
						break;
					}
				}
			}
		}

		// Close file
		f.close();
	} else {
		this->log->error("Unable to open datafile for update!");
		return false;
	}

	if (!recordFound) {
		this->log->warning("Unable to remove " + filePath + " from data file, record not found in data file!");
		return false;
	} else {
		return true;
	}
}

/*
 * Sort std::vector<hb::SuspiciosAddressStatType> descending by activityCount
 */
bool Data::sortByActivityCount(const hb::SuspiciosAddressStatType& la, const hb::SuspiciosAddressStatType& ra)
{
	return la.activityCount > ra.activityCount;
}

/*
 * Sort std::vector<hb::SuspiciosAddressStatType> descending by lastActivity
 */
bool Data::sortByLastActivity(const hb::SuspiciosAddressStatType& la, const hb::SuspiciosAddressStatType& ra)
{
	return la.lastActivity > ra.lastActivity;
}

/*
 * Return formatted datetime string
 */
std::string Data::formatDateTime(const time_t rtime, const char* dateTimeFormat)
{
	struct tm* itime = localtime(&rtime);
	char buffer[30];
	strftime(buffer, sizeof(buffer), dateTimeFormat, itime);
	return std::string(buffer);
}

/*
 * Pad string on both sides to center
 */
std::string Data::centerString(std::string str, unsigned int len)
{
	// If string length is already greater than len provided, then there is no work to be done
	if (str.length() < len) {
		unsigned int padLeft = floor((len - str.length()) / 2);
		unsigned int padRight = padLeft;
		if ((len - str.length()) % 2 != 0) padRight++;
		// std::cout << padLeft << ":" << padRight << std::endl;
		str = std::string(padLeft, ' ') + str + std::string(padRight, ' ');
	}
	return str;
}

/*
 * Print (stdout) some statistics about data
 */
void Data::printStats()
{
	std::cout << "Total suspicious IP address count: " << this->suspiciousAddresses.size() << std::endl;

	if (this->suspiciousAddresses.size() > 0) {
		std::cout << std::endl;
		std::map<std::string, SuspiciosAddressType>::iterator sait;
		std::vector<hb::SuspiciosAddressStatType> top5;
		std::vector<hb::SuspiciosAddressStatType>::iterator t5it;
		hb::SuspiciosAddressStatType address;
		std::vector<hb::SuspiciosAddressStatType> last5;
		std::vector<hb::SuspiciosAddressStatType>::iterator l5it;
		unsigned int lastActivityMaxLen = 13;
		unsigned int activityScoreMaxLen = 5;
		unsigned int activityCountMaxLen = 5;
		unsigned int refusedCountMaxLen = 7;
		unsigned int tmp = 0;

		// Get top 5 addresses by activity count and last 5 addresses by last activity time
		for (sait = this->suspiciousAddresses.begin(); sait!=this->suspiciousAddresses.end(); ++sait) {
			address.address = sait->first;
			address.lastActivity = sait->second.lastActivity;
			address.activityScore = sait->second.activityScore;
			address.activityCount = sait->second.activityCount;
			address.refusedCount = sait->second.refusedCount;

			if (top5.size() < 5) {
				// First fill up top5
				top5.push_back(address);
			} else {
				// Once top5 is filled, check if other records have better count
				for (t5it = top5.begin(); t5it != top5.end(); ++t5it) {
					if (address.activityCount > t5it->activityCount) {
						top5.erase(t5it);
						top5.push_back(address);
						break;
					}
				}
			}

			if (last5.size() < 5) {
				// First fill up last5
				last5.push_back(address);
			} else {
				// Once last5 is filled, check if other records have more recent last activity
				for (l5it = last5.begin(); l5it != last5.end(); ++l5it) {
					if (address.lastActivity > l5it->lastActivity) {
						last5.erase(l5it);
						last5.push_back(address);
						break;
					}
				}
			}
		}

		// Sort top5 addresses
		std::sort(top5.begin(), top5.end(), this->sortByActivityCount);

		// Sort last5 addresses
		std::sort(last5.begin(), last5.end(), this->sortByLastActivity);

		// Calculate needed padding
		tmp = formatDateTime((const time_t)top5[0].lastActivity, this->config->dateTimeFormat.c_str()).length();
		if (tmp > lastActivityMaxLen) lastActivityMaxLen = tmp;
		tmp = std::to_string(top5[0].activityCount).length();
		if (tmp > activityCountMaxLen) activityCountMaxLen = tmp;
		for (t5it = top5.begin(); t5it != top5.end(); ++t5it) {
			tmp = std::to_string(t5it->activityScore).length();
			if (tmp > activityScoreMaxLen) activityScoreMaxLen = tmp;
			tmp = std::to_string(t5it->refusedCount).length();
			if (tmp > refusedCountMaxLen) refusedCountMaxLen = tmp;
		}

		// Output top 5 addresses by activity
		std::cout << "Top 5 most active addresses:" << std::endl;
		std::cout << "----------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::endl;
		std::cout << "     Address     |";
		std::cout << ' ' << hb::Data::centerString("Count", activityCountMaxLen) << " |";
		std::cout << ' ' << hb::Data::centerString("Score", activityScoreMaxLen) << " |";
		std::cout << ' ' << hb::Data::centerString("Refused", refusedCountMaxLen) << " |";
		std::cout << ' ' << hb::Data::centerString("Last activity", lastActivityMaxLen);
		std::cout << std::endl;
		std::cout << "----------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::endl;
		for (t5it = top5.begin(); t5it != top5.end(); ++t5it) {
			std::cout << " " << std::left << std::setw(15) << t5it->address;
			std::cout << " | " << hb::Data::centerString(std::to_string(t5it->activityCount), activityCountMaxLen);
			std::cout << " | " << hb::Data::centerString(std::to_string(t5it->activityScore), activityScoreMaxLen);
			std::cout << " | " << hb::Data::centerString(std::to_string(t5it->refusedCount), refusedCountMaxLen);
			std::cout << " | " << hb::Data::formatDateTime((const time_t)t5it->lastActivity, this->config->dateTimeFormat.c_str());
			std::cout << std::endl;
		}

		// Recalculate some padding
		tmp = std::to_string(last5[0].activityCount).length();
		if (tmp > activityCountMaxLen) activityCountMaxLen = tmp;
		for (l5it = last5.begin(); l5it != last5.end(); ++l5it) {
			tmp = std::to_string(l5it->activityScore).length();
			if (tmp > activityScoreMaxLen) activityScoreMaxLen = tmp;
			tmp = std::to_string(l5it->refusedCount).length();
			if (tmp > refusedCountMaxLen) refusedCountMaxLen = tmp;
		}

		// Output last 5 addresses by last activity
		std::cout << std::endl << "Last activity:" << std::endl;
		std::cout << "----------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::endl;
		std::cout << "     Address     |";
		std::cout << ' ' << hb::Data::centerString("Count", activityCountMaxLen) << " |";
		std::cout << ' ' << hb::Data::centerString("Score", activityScoreMaxLen) << " |";
		std::cout << ' ' << hb::Data::centerString("Refused", refusedCountMaxLen) << " |";
		std::cout << ' ' << hb::Data::centerString("Last activity", lastActivityMaxLen);
		std::cout << std::endl;
		std::cout << "----------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::endl;
		for (l5it = last5.begin(); l5it != last5.end(); ++l5it) {
			std::cout << " " << std::left << std::setw(15) << l5it->address;
			std::cout << " | " << hb::Data::centerString(std::to_string(l5it->activityCount), activityCountMaxLen);
			std::cout << " | " << hb::Data::centerString(std::to_string(l5it->activityScore), activityScoreMaxLen);
			std::cout << " | " << hb::Data::centerString(std::to_string(l5it->refusedCount), refusedCountMaxLen);
			std::cout << " | " << hb::Data::formatDateTime((const time_t)l5it->lastActivity, this->config->dateTimeFormat.c_str());
			std::cout << std::endl;
		}
	}
}
