/*
 * Class to work with suspicious activity and log file data. Read further for
 * small details about how data file looks like.
 *
 * First position means type of record, almost all data is in fixed position
 * left padded with space to fill specified len. As exception to fixed position
 * is file_path. If filename will change, old one will be marked for removal and
 * new one added to end of file. Delete replaces first position of record with
 * "r". Daemon start checks for removed record count, if it exceeds 100, data
 * file is rewritten with latest data and lines starting with "r" are not saved
 * (to get rid of them eventually).
 *
 * Data about suspicious activity from address:
 * d|addr|lastact|actscore|actcount|refcount|whitelisted|blacklisted|lastreport
 *
 * Log file bookmark to check for log rotation and for seekg to read only new
 * lines:
 * b|bookmark|size|file_path
 *
 * Data about IP address received from AbuseIPDB (API blacklist endpoint)
 * a|addr|repcount|confscore
 *
 * Status of data synchronization with AbuseIPDB (API blacklist endpoint)
 * s|synctime|gentime
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
 * lastreport  - unix timestamp of last report to AbuseIPDB, len 20
 *
 * bookmark    - bookmark with how far this file is already parsed, len 20
 * size        - size of file when it was last read, len 20
 * file_path   - full path to log file, variable len (limits.h/PATH_MAX is not
 *               reliable so no max len here)
 *
 * repcount    - AbuseIPDB report count, len 10
 * confscore   - AbuseIPDB confidence score, len 3
 *               (https://www.abuseipdb.com/faq.html#confidence)
 *
 * synctime    - unix timestamp of last syncrhonization with AbuseIPDB, len 20
 * gentime     - blacklist generation timestamp returned by AbuseIPDB, len 20
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
// C Math
#include <cmath>
// Linux stat
namespace cstat{
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
}
// File control options (lockf)
namespace cfcntl{
	#include <fcntl.h>
}
// Miscellaneous UNIX symbolic constants, types and functions (open, usleep)
namespace cunistd{
	#include <unistd.h>
}
// GNU extensions for working with standard C FILE* and POSIX file descriptors
#include <ext/stdio_filebuf.h>
// Limits
#include <climits>
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
	this->log->debug("Loading data from " + this->config->dataFilePath);

	// Open file
	FILE* fp = std::fopen(this->config->dataFilePath.c_str(), "r");
	if (fp == NULL) {
		this->log->warning(std::to_string(errno) + ": " + strerror(errno));
		this->log->warning("Unable to open datafile for reading!");
		if (this->saveData() == false) {
			this->log->error("Error " + std::to_string(errno) + ": " + strerror(errno));
			this->log->error("Failed to create new datafile!");
		}
		return false;
	}

	// Get file descriptor
	int fd = fileno(fp);
	if (fd == -1) {
		std::fclose(fp);
		this->log->error("Error " + std::to_string(errno) + ": " + strerror(errno));
		this->log->error("Unable to read datafile, failed to get file descriptor!");
		return false;
	}

	// Do not start full read during long running writes from other processes
	int fs = cfcntl::lockf(fd, F_TEST, 0);
	// int fs = cfcntl::lockf(fd, F_LOCK, 0);
	unsigned int retryCounter = 1;
	while (fs == -1) {
		if (retryCounter >= 3) {
			break;
		}
		// Sleep
		cunistd::usleep(500000);
		// Retry
		fs = cfcntl::lockf(fd, F_TEST, 0);
		// fs = cfcntl::lockf(fd, F_LOCK, 0);
		++retryCounter;
	}
	if (fs == -1) {
		std::fclose(fp);
		this->log->error("Error " + std::to_string(errno) + ": " + strerror(errno));
		this->log->error("Unable to read datafile, file is locked!");
		return false;
	}

	// Associate stream buffer with an open POSIX file descriptor
	__gnu_cxx::stdio_filebuf<char> filebuf(fd, std::ios::in);
	std::istream f(&filebuf);

	// Init vars for parsing
	std::string line;
	char recordType;
	std::string address;
	hb::SuspiciosAddressType data;
	std::pair<std::map<std::string, hb::SuspiciosAddressType>::iterator,bool> chk;
	hb::AbuseIPDBBlacklistedAddressType abuseIPDBData;
	std::pair<std::map<std::string, hb::AbuseIPDBBlacklistedAddressType>::iterator,bool> chka;
	bool duplicatesFound = false;
	unsigned long long int bookmark, size;
	std::string logFilePath;
	bool logFileFound = false;
	std::vector<hb::LogGroup>::iterator itlg;
	std::vector<hb::LogFile>::iterator itlf;
	unsigned int removedRecords = 0;
	bool needUpgrade = false;

	// Clear this->suspiciousAddresses
	this->suspiciousAddresses.clear();

	// Clear this->abuseIPDBBlacklist
	this->abuseIPDBBlacklist.clear();

	// Read data file line by line
	while (std::getline(f, line)) {

		// First position is record type
		recordType = line[0];

		if (recordType == 'd' && (line.length() == 92 || line.length() == 112)) {// Data about suspicious address

			// IP address
			address = hb::Util::ltrim(line.substr(1, 39));

			// Timestamp of last activity
			data.lastActivity = std::strtoull(hb::Util::ltrim(line.substr(40, 20)).c_str(), NULL, 10);

			// Total score of activity calculated at last activity
			data.activityScore = std::strtoul(hb::Util::ltrim(line.substr(60, 10)).c_str(), NULL, 10);

			// Suspicious activity count
			data.activityCount = std::strtoul(hb::Util::ltrim(line.substr(70, 10)).c_str(), NULL, 10);

			// Refused connection count
			data.refusedCount = std::strtoul(hb::Util::ltrim(line.substr(80, 10)).c_str(), NULL, 10);

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

			// Timestamp of last report to 3rd party
			// TODO, introduce data file version to handle upgrade
			if (line.length() == 112) {
				data.lastReported = std::strtoull(hb::Util::ltrim(line.substr(92, 20)).c_str(), NULL, 10);
			} else {
				needUpgrade = true;
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
			bookmark = std::strtoull(hb::Util::ltrim(line.substr(1, 20)).c_str(), NULL, 10);

			// Last known size to detect if log file has been rotated
			size = std::strtoull(hb::Util::ltrim(line.substr(21, 20)).c_str(), NULL, 10);

			// Path to log file
			logFilePath = hb::Util::rtrim(hb::Util::ltrim(line.substr(41)));

			// Update info about log file
			logFileFound = false;
			for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
				for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
					if (itlf->path == logFilePath) {
						itlf->bookmark = bookmark;
						itlf->size = size;
						itlf->dataFileRecord = true;
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

		} else if (recordType == 'a') {// AbuseIPDB blacklisted address

			// IP address
			address = hb::Util::ltrim(line.substr(1, 39));

			// AbuseIPDB report count for this IP address according to specified interval
			abuseIPDBData.totalReports = std::strtoul(hb::Util::ltrim(line.substr(40, 10)).c_str(), NULL, 10);

			// AbuseIPDB confidence score
			abuseIPDBData.abuseConfidenceScore = std::strtoul(hb::Util::ltrim(line.substr(50, 3)).c_str(), NULL, 10);

			// When data is loaded from datafile we do not have yet info whether it has rule in iptables, this will be changed to true later if needed
			abuseIPDBData.iptableRule = false;

			// Store in this->abuseIPDBBlacklist
			chka = this->abuseIPDBBlacklist.insert(std::pair<std::string, hb::AbuseIPDBBlacklistedAddressType>(address, abuseIPDBData));
			if (chka.second == false) {
				this->log->warning("AbuseIPDB blacklisted address" + address + " is duplicated in data file, new datafile without duplicates will be created!");
				duplicatesFound = true;
			}

		} else if (recordType == 's') {// AbuseIPDB sync bookmark

			// Unix timestamp of last sync with AbuseIPDB using blacklist endpoint
			this->abuseIPDBSyncTime = std::strtoull(hb::Util::ltrim(line.substr(1, 20)).c_str(), NULL, 10);

			// Unix timestamp of AbuseIPDB blacklist generation (returned by AbuseIPDB)
			this->abuseIPDBBlacklistGenTime =  std::strtoull(hb::Util::ltrim(line.substr(21, 20)).c_str(), NULL, 10);

		} else if (recordType == 'r') {// Record marked for removal
			removedRecords++;
		}
	}

	// Finished reading file
	std::fclose(fp);

	// Check if all configured log files are present in datafile (add if needed)
	for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
		for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
			if (!itlf->dataFileRecord) {
				this->addFile(itlf->path);
				itlf->dataFileRecord = true;
			}
		}
	}

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
	} else if (needUpgrade) {// Need to upgrade datafile
		this->log->info("Datafile requires upgrade! Saving new datafile...");
		if (this->saveData() == false) {
			this->log->error("Data file requires upgrade, tried saving new data file, but failed!");
			return false;
		}
	}

	// Data file processing finished
	this->log->debug("Loaded " + std::to_string(this->suspiciousAddresses.size()) + " IP address record(s)");

	return true;
}

/*
 * Save this->suspiciousAddresses to data file, will replace if file already exists
 */
bool Data::saveData()
{
	this->log->info("Updating datafile " + this->config->dataFilePath);

	// Open file (overwrite)
	FILE* fp = std::fopen(this->config->dataFilePath.c_str(), "w");
	if (fp == NULL) {
		this->log->error("Unable to open datafile for writing!");
		return false;
	}

	// Get file descriptor
	int fd = fileno(fp);
	if (fd == -1) {
		std::fclose(fp);
		this->log->error("Error " + std::to_string(errno) + ": " + strerror(errno));
		this->log->error("Unable to write to datafile, failed to get file descriptor!");
		return false;
	}

	// Lock file
	int fs = cfcntl::lockf(fd, F_LOCK, 0);
	unsigned int retryCounter = 1;
	while (fs == -1) {
		if (retryCounter >= 3) {
			break;
		}
		// Sleep
		cunistd::usleep(500000);
		// Retry
		fs = cfcntl::lockf(fd, F_LOCK, 0);
		++retryCounter;
	}
	if (fs == -1) {
		std::fclose(fp);
		this->log->error("Error " + std::to_string(errno) + ": " + strerror(errno));
		this->log->error("Unable to write to datafile, file is locked!");
		return false;
	}

	// Associate stream buffer with an open POSIX file descriptor
	__gnu_cxx::stdio_filebuf<char> filebuf(fd, std::ios::out);
	std::ostream f(&filebuf);

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
		f << std::right << std::setw(20) << it->second.lastReported;// Last report, left padded with spaces
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
			f << std::endl;// endl should flush buffer
		}
	}

	// Loop all AbuseIPDB blacklisted addresses
	std::map<std::string, AbuseIPDBBlacklistedAddressType>::iterator itb;
	for (itb = this->abuseIPDBBlacklist.begin(); itb!=this->abuseIPDBBlacklist.end(); ++itb) {
		f << 'a';
		f << std::right << std::setw(39) << itb->first;// Address, left padded with spaces
		f << std::right << std::setw(10) << itb->second.totalReports;
		if (itb->second.abuseConfidenceScore <= 100) {
			f << std::right << std::setw(3) << itb->second.abuseConfidenceScore;
		} else {
			f << std::right << std::setw(3) << 0;
		}
		f << "\n";// \n should not flush buffer
	}

	// Bookmark of last sync with AbuseIPDB and blacklist generation timestamp
	f << 's';
	f << std::right << std::setw(20) << this->abuseIPDBSyncTime;
	f << std::right << std::setw(20) << this->abuseIPDBBlacklistGenTime;
	f << std::endl;// endl should flush buffer

	// Unlock file
	fs = cfcntl::lockf(fd, F_ULOCK, 0);
	if (fs == -1) {
		this->log->warning("Failed to unlock datafile after overwrite!");
	}

	// Close datafile
	std::fclose(fp);

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
		std::size_t checkStart = 0, checkEnd = 0;
		std::map<std::string, hb::SuspiciosAddressType>::iterator sait;
		std::smatch regexSearchResults;
		std::string regexSearchResult;
		std::size_t posip = this->config->iptablesRule.find("%i");
		std::string ruleStart = "";
		std::string ruleEnd = "";
		if (posip != std::string::npos) {
			ruleStart = this->config->iptablesRule.substr(0, posip);
			ruleEnd = this->config->iptablesRule.substr(posip + 2);
		}

		for (rit=rules.begin(); rit!=rules.end(); ++rit) {

			// Searching for rules similar to ones that are in hostblock configuration to detect if address has iptables rule
			checkStart = rit->second.find(ruleStart);
			checkEnd = rit->second.find(ruleEnd);
			if (checkStart != std::string::npos && checkEnd != std::string::npos) {

				// Find address in rule
				if (std::regex_search(rit->second, regexSearchResults, ipSearchPattern)) {
					if (regexSearchResults.size() == 1) {
						regexSearchResult = regexSearchResults[0].str();

						// Search for address in map
						sait = this->suspiciousAddresses.find(regexSearchResult);
						if (sait != this->suspiciousAddresses.end()) {
							if (sait->second.iptableRule == false) {
								sait->second.iptableRule = true;
							} else {
								this->log->warning("Found duplicate iptables rule for " + sait->first + ", consider:");
								this->log->warning("$ sudo iptables --list-rules INPUT | grep " + sait->first);
								this->log->warning("$ sudo iptables -D INPUT " + ruleStart + sait->first + ruleEnd);
							}

						} else {
							this->log->warning("Found iptables rule for " + regexSearchResult + " but don't have any information about this address in datafile, please review manually.");
							this->log->warning("$ sudo iptables --list-rules INPUT | grep " + regexSearchResult);
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
					// Without multiplier rules are kept until score is reset to 0
					if (sait->second.activityScore == 0) {
						removeRule = true;
					}
				}
			}
			if (createRule == true) {
				this->log->info("Address " + sait->first + " is missing iptables rule, adding...");
				try {
					// Append rule
					if (this->iptables->append("INPUT", ruleStart + sait->first + ruleEnd) == false) {
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
				this->log->info("Address " + sait->first + " iptables rule expired, removing...");
				try {
					// Remove rule
					if (this->iptables->remove("INPUT", ruleStart + sait->first + ruleEnd) == false) {
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

	// Open file (overwrite)
	FILE* fp = std::fopen(this->config->dataFilePath.c_str(), "a");
	if (fp == NULL) {
		this->log->error("Unable to open datafile for writing!");
		return false;
	}

	// Get file descriptor
	int fd = fileno(fp);
	if (fd == -1) {
		std::fclose(fp);
		this->log->error("Error " + std::to_string(errno) + ": " + strerror(errno));
		this->log->error("Unable to write to datafile, failed to get file descriptor!");
		return false;
	}

	// Lock file
	int fs = cfcntl::lockf(fd, F_LOCK, 113);
	unsigned int retryCounter = 1;
	while (fs == -1) {
		if (retryCounter >= 3) {
			break;
		}
		// Sleep
		cunistd::usleep(500000);
		// Retry
		fs = cfcntl::lockf(fd, F_LOCK, 113);
		++retryCounter;
	}
	if (fs == -1) {
		std::fclose(fp);
		this->log->error("Error " + std::to_string(errno) + ": " + strerror(errno));
		this->log->error("Unable to write to datafile, file is locked!");
		return false;
	}

	// Associate stream buffer with an open POSIX file descriptor
	__gnu_cxx::stdio_filebuf<char> filebuf(fd, std::ios::out);
	std::ostream f(&filebuf);

	// Write record to the end of datafile
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
	f << std::right << std::setw(20) << this->suspiciousAddresses[address].lastReported;// Last report, left padded with spaces
	f << std::endl;

	// Unlock file
	fs = cfcntl::lockf(fd, F_ULOCK, 0);
	if (fs == -1) {
		this->log->warning("Failed to unlock datafile after overwrite!");
	}

	// Close datafile
	std::fclose(fp);

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
					f << std::right << std::setw(20) << this->suspiciousAddresses[address].lastReported;// Last report, left padded with spaces
					f << std::endl;// endl should flush buffer
					recordFound = true;

					// No need to continue reading file
					break;
				}
				// std::cout << "Address: " << hb::Util::ltrim(std::string(fAddress)) << " tellg: " << std::to_string(f.tellg()) << std::endl;
				f.seekg(73, f.cur);
			} else {// Other type of record (file bookmark or removed record)
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
				f.seekg(73, f.cur);
			} else {// Variable length record (file bookmark or removed record)
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
		return false;
	} else {
		return true;
	}
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
					f << std::endl;// endl should flush buffer
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
				f.seekg(112, f.cur);
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
				f.seekg(112, f.cur);
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
 * Add new record to datafile based on this->abuseIPDBBlacklist
 */
bool Data::addAbuseIPDBAddress(std::string address)
{
	this->log->debug("Adding AbuseIPDB blacklist record to " + this->config->dataFilePath + ", address " + address);
	std::ofstream f(this->config->dataFilePath.c_str(), std::ofstream::out | std::ofstream::app);
	if (f.is_open()) {
		// Write record to the end of datafile
		f << 'a';
		f << std::right << std::setw(39) << address;
		f << std::right << std::setw(10) << this->abuseIPDBBlacklist[address].totalReports;
		if (this->abuseIPDBBlacklist[address].abuseConfidenceScore > 999) {
			this->abuseIPDBBlacklist[address].abuseConfidenceScore = 999;
		}
		f << std::right << std::setw(3) << this->abuseIPDBBlacklist[address].abuseConfidenceScore;
		f << std::endl;// endl should flush buffer

		// Close datafile
		f.close();
	} else {
		this->log->error("Unable to open datafile for writting!");
		return false;
	}

	return true;
}

/*
 * Update record in datafile based on this->abuseIPDBBlacklist
 */
bool Data::updateAbuseIPDBAddress(std::string address)
{
	bool recordFound = false;
	char c;
	char fAddress[40];
	this->log->debug("Updating AbuseIPDB blacklist record in " + this->config->dataFilePath + ", updating address " + address);
	std::fstream f(this->config->dataFilePath.c_str(), std::fstream::in | std::fstream::out);
	if (f.is_open()) {
		while (f.get(c)) {
			if (c == 'a') {// AbuseIPDB blacklist record, check if address matches

				// Get address
				f.get(fAddress, 40);

				// If we have found address that we need to update
				if (hb::Util::ltrim(std::string(fAddress)) == address) {
					f << std::right << std::setw(10) << this->abuseIPDBBlacklist[address].totalReports;
					if (this->abuseIPDBBlacklist[address].abuseConfidenceScore > 999) {
						this->abuseIPDBBlacklist[address].abuseConfidenceScore = 999;
					}
					f << std::right << std::setw(3) << this->abuseIPDBBlacklist[address].abuseConfidenceScore;
					// f << std::endl;// endl should flush buffer
					f << "\n";// \n should not flush buffer
					recordFound = true;

					// No need to continue reading file
					break;
				}
				f.seekg(14, f.cur);
			} else {// Other type of record (suspicious activity, file bookmark or removed record)
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
		this->log->error("Unable to update " + address + " in data file, AbuseIPDB blacklist record not found in data file!");
		return false;
	} else {
		return true;
	}
}

/*
 * Mark AbuseIPDB blacklist record for removal in datafile
 */
bool Data::removeAbuseIPDBAddress(std::string address)
{
	bool recordFound = false;
	char c;
	char fAddress[40];
	// std:string buffer;
	this->log->debug("Removing AbuseIPDB blacklist record from " + this->config->dataFilePath + ", removing address " + address);
	std::fstream f(this->config->dataFilePath.c_str(), std::fstream::in | std::fstream::out);
	if (f.is_open()) {
		while (f.get(c)) {
			if (c == 'a') {// AbuseIPDB blacklist record, check if address matches

				// Get address
				f.get(fAddress, 40);

				// If we have found address that we need to remove
				if (hb::Util::ltrim(std::string(fAddress)) == address) {
					f.seekg(-40, f.cur);
					f << 'r';
					recordFound = true;
					break;// No need to continue reading file
				}
				f.seekg(14, f.cur);
			} else {// Variable length record (file bookmark or removed record)
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
		return false;
	} else {
		return true;
	}
}

/*
 * Add/remove iptables rule based on score and blacklist
 */
bool Data::updateIptables(std::string address)
{
	bool createRule = false;
	bool removeRule = false;

	std::time_t currentRawTime;
	std::time(&currentRawTime);
	unsigned long long int currentTime = (unsigned long long int)currentRawTime;

	// Remove rule if address not present in local data file and is not listed in AbuseIPDB blacklist
	if (this->suspiciousAddresses.count(address) == 0 && this->abuseIPDBBlacklist.count(address) == 0) {
		removeRule = true;
	}

	// Check whether need to create rule based on AbuseIPDB blacklist
	if (this->abuseIPDBBlacklist.count(address) > 0) {
		if (this->abuseIPDBBlacklist[address].iptableRule == false) {
			if (this->abuseIPDBBlacklist[address].abuseConfidenceScore >= this->config->abuseipdbBlockScore) {
				createRule = true;
			}
		}
	}

	// Check whether need to add/remove rule for address based on hostblock data
	if (this->suspiciousAddresses.count(address) > 0) {
		// Check new score and see if need to add to/remove from iptables
		if (this->suspiciousAddresses[address].iptableRule) {// Rule exists, check if need to remove

			// Whitelisted addresses must not have rule
			if (this->suspiciousAddresses[address].whitelisted == true) {
				removeRule = true;
			}

			// Keep rule for locally blacklisted addresses or if address is in AbuseIPDB blacklist
			if (this->suspiciousAddresses[address].blacklisted == false && createRule == false) {
				if (this->config->keepBlockedScoreMultiplier > 0) {
					// Score multiplier configured, recheck if score is no longer high enough to keep this rule
					if (currentTime > this->suspiciousAddresses[address].lastActivity + this->suspiciousAddresses[address].activityScore) {
						removeRule = true;
					}
				} else {
					// Without score multiplier rules are kept unless score is 0
					if (this->suspiciousAddresses[address].activityScore == 0) {
						removeRule = true;
					}
				}
			}
		} else {// Rule does not exist, check if need to add

			// Blacklisted addresses must have rule
			if (this->suspiciousAddresses[address].blacklisted == true && this->suspiciousAddresses[address].whitelisted == false) {
				createRule = true;
			}

			// Whitelisted addresses must not have rule
			if (this->suspiciousAddresses[address].whitelisted == false && createRule == false) {
				if (this->config->keepBlockedScoreMultiplier > 0) {
					// Score multiplier configured, check if score is high enough to create rule
					if (this->suspiciousAddresses[address].activityScore > 0
							&& this->suspiciousAddresses[address].lastActivity + this->suspiciousAddresses[address].activityScore > this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier
							&& currentTime < (this->suspiciousAddresses[address].lastActivity + this->suspiciousAddresses[address].activityScore) - (this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier)) {
						createRule = true;
					}
				} else {
					// Without score multiplier rules are created unless score is 0
					if (this->suspiciousAddresses[address].activityScore > this->config->activityScoreToBlock) {
						createRule = true;
					}
				}
			}
		}
	}

	// Adjust iptables rules
	std::string ruleStart = "";
	std::string ruleEnd = "";
	if (createRule == true || removeRule == true) {
		std::size_t posip = this->config->iptablesRule.find("%i");
		if (posip != std::string::npos) {
			ruleStart = this->config->iptablesRule.substr(0, posip);
			ruleEnd = this->config->iptablesRule.substr(posip + 2);
		}
	}
	if (createRule == true) {
		this->log->info("Adding rule for " + address + " to iptables chain!");
		try {
			if (this->iptables->append("INPUT", ruleStart + address + ruleEnd) == false) {
				this->log->error("Address " + address + " should have iptables rule, but hostblock failed to append rule to chain!");
				return false;
			} else {
				if (this->suspiciousAddresses.count(address) > 0) {
					this->suspiciousAddresses[address].iptableRule = true;
				}
				if (this->abuseIPDBBlacklist.count(address) > 0) {
					this->abuseIPDBBlacklist[address].iptableRule = true;
				}
			}
		} catch (std::runtime_error& e) {
			std::string message = e.what();
			this->log->error(message);
			this->log->error("Address " + address + " should have iptables rule, but hostblock failed to append rule to chain!");
			return false;
		}
	}
	if (removeRule == true) {
		this->log->info("Removing rule for " + address + " from iptables chain!");
		try {
			if(this->iptables->remove("INPUT", ruleStart + address + ruleEnd) == false){
				this->log->error("Address " + address + " no longer needs iptables rule, but failed to remove rule from chain!");
				return false;
			} else {
				if (this->suspiciousAddresses.count(address) > 0) {
					this->suspiciousAddresses[address].iptableRule = false;
				}
				if (this->abuseIPDBBlacklist.count(address) > 0) {
					this->abuseIPDBBlacklist[address].iptableRule = false;
				}
			}
		} catch (std::runtime_error& e) {
			std::string message = e.what();
			this->log->error(message);
			this->log->error("Address " + address + " no longer needs iptables rule, but failed to remove rule from chain!");
			return false;
		}
	}

	return true;
}

/*
 * Save suspicious activity to data->suspiciousAddreses and datafile (add new or update existing)
 * Additionally add/remove iptables rule
 */
void Data::saveActivity(std::string address, unsigned int activityScore, unsigned int activityCount, unsigned int refusedCount)
{
	std::time_t currentRawTime;
	std::time(&currentRawTime);
	unsigned long long int currentTime = (unsigned long long int)currentRawTime;

	// Warning if only last activity time changes
	if (activityScore == 0 && activityCount == 0 && refusedCount == 0) {
		this->log->warning("Trying to register suspicious activity, but no data about activity! Only last activity time for address " + address + " will be updated!");
	}

	// Check if new record needs to be added or we need to update existing data
	bool newEntry = false;
	if (this->suspiciousAddresses.count(address) > 0) {

		// This address already had some activity previously, need to recalculate score
		this->log->debug("Previous activity: " + std::to_string(this->suspiciousAddresses[address].lastActivity));

		// Adjust old score according to time passed
		if (this->config->keepBlockedScoreMultiplier > 0 && this->suspiciousAddresses[address].activityScore > 0) {
			this->log->debug("Adjusting previous score according to time passed...");
			if (this->suspiciousAddresses[address].activityScore < currentTime - this->suspiciousAddresses[address].lastActivity) {
				this->suspiciousAddresses[address].activityScore = 0;
			} else {
				this->suspiciousAddresses[address].activityScore -= currentTime - this->suspiciousAddresses[address].lastActivity;
			}
		}

		// Last activity is now
		this->suspiciousAddresses[address].lastActivity = currentTime;

		// Use score multiplier for score that needs to be added to old one
		if (this->config->keepBlockedScoreMultiplier > 0) {
			this->log->debug("Adjusting new score according to multiplier...");
			activityScore = activityScore * this->config->keepBlockedScoreMultiplier;
		}

		// Increase score
		if (this->suspiciousAddresses[address].activityScore + activityScore < this->suspiciousAddresses[address].activityScore) {
			this->suspiciousAddresses[address].activityScore = UINT_MAX;
		} else {
			this->suspiciousAddresses[address].activityScore += activityScore;
		}
		if (this->suspiciousAddresses[address].activityCount + activityCount < this->suspiciousAddresses[address].activityCount) {
			this->suspiciousAddresses[address].activityCount = UINT_MAX;
		} else {
			this->suspiciousAddresses[address].activityCount += activityCount;
		}
		if (this->suspiciousAddresses[address].refusedCount + refusedCount < this->suspiciousAddresses[address].refusedCount) {
			this->suspiciousAddresses[address].refusedCount = UINT_MAX;
		} else {
			this->suspiciousAddresses[address].refusedCount += refusedCount;
		}

	} else {

		// First time activity from this address
		SuspiciosAddressType data;
		data.lastActivity = currentTime;

		// Set score
		if (this->config->keepBlockedScoreMultiplier > 0) {
			data.activityScore = activityScore * this->config->keepBlockedScoreMultiplier;
		} else {
			data.activityScore = activityScore;
		}

		data.activityCount = activityCount;
		data.refusedCount = refusedCount;
		data.whitelisted = false;
		data.blacklisted = false;
		data.lastReported = 0;
		this->suspiciousAddresses.insert(std::pair<std::string,SuspiciosAddressType>(address,data));
		newEntry = true;
	}

	// Few details for debug
	this->log->debug("Last activity: " + std::to_string(this->suspiciousAddresses[address].lastActivity));
	this->log->debug("Activity score: " + std::to_string(this->suspiciousAddresses[address].activityScore));
	this->log->debug("Activity count: " + std::to_string(this->suspiciousAddresses[address].activityCount));
	this->log->debug("Refused count: " + std::to_string(this->suspiciousAddresses[address].refusedCount));
	if (this->suspiciousAddresses[address].whitelisted) this->log->debug("Address is in whitelist!");
	if (this->suspiciousAddresses[address].blacklisted) this->log->debug("Address is in blacklist!");
	this->log->debug("Last reported: " + std::to_string(this->suspiciousAddresses[address].lastReported));

	this->updateIptables(address);

	// Update data file
	if (newEntry == true) {
		// Add new entry to end of data file
		this->addAddress(address);
	} else {
		// Update entry in data file
		this->updateAddress(address);
	}
}

/*
 * Save AbuseIPDB blacklist record in data->abuseIPDBBlacklist and datafile (add new or update existing)
 * Additionally add/remove iptables rule
 */
void Data::saveAbuseIPDBRecord(std::string address, unsigned int totalReports, unsigned int abuseConfidenceScore)
{
	bool newEntry = false;

	if (this->abuseIPDBBlacklist.count(address) > 0) {
		this->abuseIPDBBlacklist[address].totalReports = totalReports;
		this->abuseIPDBBlacklist[address].abuseConfidenceScore = abuseConfidenceScore;
	} else {
		AbuseIPDBBlacklistedAddressType data;
		data.totalReports = totalReports;
		data.abuseConfidenceScore = abuseConfidenceScore;
		data.iptableRule = false;
		this->abuseIPDBBlacklist.insert(std::pair<std::string,AbuseIPDBBlacklistedAddressType>(address,data));
		newEntry = true;
	}

	this->updateIptables(address);

	// Update data file
	if (newEntry == true) {
		this->addAbuseIPDBAddress(address);
	} else {
		this->updateAbuseIPDBAddress(address);
	}
}

/*
 * Sort std::vector<hb::SuspiciosAddressStatType> descending by activityCount
 */
bool Data::sortByActivityCount(const hb::SuspiciosAddressStatType& la, const hb::SuspiciosAddressStatType& ra)
{
	return (unsigned long int)la.activityCount + la.refusedCount > (unsigned long int)ra.activityCount + ra.refusedCount;
}

/*
 * Sort std::vector<hb::SuspiciosAddressStatType> descending by lastActivity
 */
bool Data::sortByLastActivity(const hb::SuspiciosAddressStatType& la, const hb::SuspiciosAddressStatType& ra)
{
	return la.lastActivity > ra.lastActivity;
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
		unsigned int statusMaxLen = 7;
		unsigned int tmp = 0;
		std::time_t currentRawTime;
		std::time(&currentRawTime);
		unsigned long long int currentTime = (unsigned long long int)currentRawTime;
		unsigned int activityCountMin = UINT_MAX;
		unsigned long long int lastActivityMin = ULLONG_MAX;
		bool replace = false;
		unsigned int totalBlocked = 0;
		unsigned int totalWhitelisted = 0;
		unsigned int totalBlacklisted = 0;
		unsigned int totalActivityCout = 0;
		unsigned int totalRefusedCount = 0;

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
				replace = false;

				// Find min activity count
				activityCountMin = UINT_MAX;
				for (t5it = top5.begin(); t5it != top5.end(); ++t5it) {
					if (t5it->activityCount + t5it->refusedCount >= t5it->activityCount
						&& t5it->activityCount + t5it->refusedCount >= t5it->refusedCount) {
						if (t5it->activityCount + t5it->refusedCount < activityCountMin) {
							activityCountMin = t5it->activityCount + t5it->refusedCount;
						}
					}
				}

				// Check if there is record with more activity
				if (address.activityCount + address.refusedCount < address.activityCount
					|| address.activityCount + address.refusedCount < address.refusedCount) {
					if (UINT_MAX > activityCountMin) {
						replace = true;
					}
				} else{
					if (address.activityCount + address.refusedCount > activityCountMin) {
						replace = true;
					}
				}

				// Replace if needed
				if (replace) {
					for (t5it = top5.begin(); t5it != top5.end(); ++t5it) {
						if (t5it->activityCount + t5it->refusedCount >= t5it->activityCount
						&& t5it->activityCount + t5it->refusedCount >= t5it->refusedCount) {
							if (t5it->activityCount + t5it->refusedCount == activityCountMin) {
								top5.erase(t5it);
								top5.push_back(address);
								break;
							}
						}
					}
				}
			}

			if (last5.size() < 5) {
				// First fill up last5
				last5.push_back(address);
			} else {
				// Find min last activity
				lastActivityMin = ULLONG_MAX;
				for (l5it = last5.begin(); l5it != last5.end(); ++l5it) {
					if (l5it->lastActivity < lastActivityMin) lastActivityMin = l5it->lastActivity;
				}

				// Once last5 is filled, check if other records have more recent last activity
				if (address.lastActivity > lastActivityMin) {
					for (l5it = last5.begin(); l5it != last5.end(); ++l5it) {
						if (l5it->lastActivity == lastActivityMin) {
							last5.erase(l5it);
							last5.push_back(address);
							break;
						}
					}
				}
			}

			// Totals
			if (sait->second.whitelisted) {
				++totalWhitelisted;
			} else if (sait->second.blacklisted) {
				++totalBlacklisted;
				++totalBlocked;
			} else if (this->config->keepBlockedScoreMultiplier > 0) {
				// Score multiplier used
				if (currentTime < (sait->second.lastActivity + sait->second.activityScore) - (this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier)) {
					++totalBlocked;
				}
			} else {
				// Score multiplier not used
				if (sait->second.activityScore > this->config->activityScoreToBlock) {
					++totalBlocked;
				}
			}
			totalActivityCout += sait->second.activityCount;
			totalRefusedCount += sait->second.refusedCount;
		}

		std::cout << "Total suspicious activity: " << totalActivityCout << std::endl;
		std::cout << "Total refused: " << totalRefusedCount << std::endl;
		std::cout << "Total whitelisted: " << totalWhitelisted << std::endl;
		std::cout << "Total blacklisted: " << totalBlacklisted << std::endl;
		std::cout << "Total blocked: " << totalBlocked << std::endl;

		if (this->abuseIPDBSyncTime > 0) {
			std::cout << "Last AbuseIPDB blacklist sync time: ";
			std::cout << Util::formatDateTime((const time_t)this->abuseIPDBSyncTime, this->config->dateTimeFormat.c_str());
			std::cout << std::endl;
		}

		if (this->abuseIPDBBlacklistGenTime > 0) {
			std::cout << "AbuseIPDB blacklist generation time: ";
			std::cout << Util::formatDateTime((const time_t)this->abuseIPDBBlacklistGenTime, this->config->dateTimeFormat.c_str());
			std::cout << std::endl;
		}

		// Sort top5 addresses
		std::sort(top5.begin(), top5.end(), this->sortByActivityCount);

		// Sort last5 addresses
		std::sort(last5.begin(), last5.end(), this->sortByLastActivity);

		// Calculate needed padding
		tmp = Util::formatDateTime((const time_t)top5[0].lastActivity, this->config->dateTimeFormat.c_str()).length();
		if (tmp > lastActivityMaxLen) lastActivityMaxLen = tmp;
		for (t5it = top5.begin(); t5it != top5.end(); ++t5it) {
			tmp = std::to_string(t5it->activityCount).length();
		if (tmp > activityCountMaxLen) activityCountMaxLen = tmp;
			tmp = std::to_string(t5it->activityScore).length();
			if (tmp > activityScoreMaxLen) activityScoreMaxLen = tmp;
			tmp = std::to_string(t5it->refusedCount).length();
			if (tmp > refusedCountMaxLen) refusedCountMaxLen = tmp;
			if (this->suspiciousAddresses[t5it->address].whitelisted
				|| this->suspiciousAddresses[t5it->address].blacklisted) {
				if (statusMaxLen < 11) statusMaxLen = 11;
			} else if (this->config->keepBlockedScoreMultiplier > 0
				&& currentTime < t5it->lastActivity + t5it->activityScore) {
				if (statusMaxLen < lastActivityMaxLen) statusMaxLen = lastActivityMaxLen;
			}
		}

		// Output top 5 addresses by activity
		std::cout << std::endl << "Top 5 most active addresses:" << std::endl;
		std::cout << "--------------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::string(statusMaxLen,'-') << std::endl;
		std::cout << "     Address     |";
		std::cout << ' ' << Data::centerString("Count", activityCountMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Score", activityScoreMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Refused", refusedCountMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Last activity", lastActivityMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Status", statusMaxLen);
		std::cout << std::endl;
		std::cout << "--------------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::string(statusMaxLen,'-') << std::endl;
		for (t5it = top5.begin(); t5it != top5.end(); ++t5it) {
			std::cout << " " << std::left << std::setw(15) << t5it->address;
			std::cout << " | " << Data::centerString(std::to_string(t5it->activityCount), activityCountMaxLen);
			std::cout << " | " << Data::centerString(std::to_string(t5it->activityScore), activityScoreMaxLen);
			std::cout << " | " << Data::centerString(std::to_string(t5it->refusedCount), refusedCountMaxLen);
			std::cout << " | " << Util::formatDateTime((const time_t)t5it->lastActivity, this->config->dateTimeFormat.c_str());
			std::cout << " | ";
			if (this->suspiciousAddresses[t5it->address].whitelisted) {
				std::cout << "whitelisted" << std::string(statusMaxLen - 11,' ');
			} else if (this->suspiciousAddresses[t5it->address].blacklisted) {
				std::cout << "blacklisted" << std::string(statusMaxLen - 11,' ');
			} else if (this->config->keepBlockedScoreMultiplier > 0) {
				// Score multiplier used
				if (currentTime < (t5it->lastActivity + t5it->activityScore) - (this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier)) {
					std::cout << Util::formatDateTime((const time_t)(t5it->lastActivity + t5it->activityScore), this->config->dateTimeFormat.c_str());
				} else {
					std::cout << std::string(statusMaxLen,' ');
				}
			} else {
				// Without score multiplier
				if (t5it->activityScore > this->config->activityScoreToBlock) {
					std::cout << "blocked" << std::string(statusMaxLen - 7,' ');
				}
			}
			std::cout << std::endl;
		}

		// Recalculate padding
		activityCountMaxLen = 5;
		activityScoreMaxLen = 5;
		refusedCountMaxLen = 7;
		statusMaxLen = 7;
		for (l5it = last5.begin(); l5it != last5.end(); ++l5it) {
			tmp = std::to_string(l5it->activityCount).length();
			if (tmp > activityCountMaxLen) activityCountMaxLen = tmp;
			tmp = std::to_string(l5it->activityScore).length();
			if (tmp > activityScoreMaxLen) activityScoreMaxLen = tmp;
			tmp = std::to_string(l5it->refusedCount).length();
			if (tmp > refusedCountMaxLen) refusedCountMaxLen = tmp;
			if (this->suspiciousAddresses[l5it->address].whitelisted
				|| this->suspiciousAddresses[l5it->address].blacklisted) {
				if (statusMaxLen < 11) statusMaxLen = 11;
			} else if (this->config->keepBlockedScoreMultiplier > 0
				&& currentTime < l5it->lastActivity + l5it->activityScore) {
				if (statusMaxLen < lastActivityMaxLen) statusMaxLen = lastActivityMaxLen;
			}
		}

		// Output 5 addresses by last activity
		std::cout << std::endl << "Last activity:" << std::endl;
		std::cout << "--------------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::string(statusMaxLen,'-') << std::endl;
		std::cout << "     Address     |";
		std::cout << ' ' << Data::centerString("Count", activityCountMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Score", activityScoreMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Refused", refusedCountMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Last activity", lastActivityMaxLen) << " |";
		std::cout << ' ' << Data::centerString("Status", statusMaxLen);
		std::cout << std::endl;
		std::cout << "--------------------------------" << std::string(activityCountMaxLen,'-') << std::string(activityScoreMaxLen,'-') << std::string(refusedCountMaxLen,'-') << std::string(lastActivityMaxLen,'-') << std::string(statusMaxLen,'-') << std::endl;
		for (l5it = last5.begin(); l5it != last5.end(); ++l5it) {
			std::cout << " " << std::left << std::setw(15) << l5it->address;
			std::cout << " | " << Data::centerString(std::to_string(l5it->activityCount), activityCountMaxLen);
			std::cout << " | " << Data::centerString(std::to_string(l5it->activityScore), activityScoreMaxLen);
			std::cout << " | " << Data::centerString(std::to_string(l5it->refusedCount), refusedCountMaxLen);
			std::cout << " | " << Util::formatDateTime((const time_t)l5it->lastActivity, this->config->dateTimeFormat.c_str());
			std::cout << " | ";
			if (this->suspiciousAddresses[l5it->address].whitelisted) {
				std::cout << "whitelisted" << std::string(statusMaxLen - 11,' ');
			} else if (this->suspiciousAddresses[l5it->address].blacklisted) {
				std::cout << "blacklisted" << std::string(statusMaxLen - 11,' ');
			} else if (this->config->keepBlockedScoreMultiplier > 0) {
				if (currentTime < (l5it->lastActivity + l5it->activityScore) - (this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier)) {
					std::cout << Util::formatDateTime((const time_t)(l5it->lastActivity + l5it->activityScore), this->config->dateTimeFormat.c_str());
				} else {
					std::cout << std::string(statusMaxLen,' ');
				}
			} else {
				// Without score multiplier
				if (l5it->activityScore > this->config->activityScoreToBlock) {
					std::cout << "blocked" << std::string(statusMaxLen - 7,' ');
				}
			}
			std::cout << std::endl;
		}
	}
}

/*
 * Print (stdout) list of all blocked addresses or all addresses (flag)
 */
void Data::printBlocked(bool count, bool time, bool all)
{
	if (this->suspiciousAddresses.size() > 0) {
		std::map<std::string, SuspiciosAddressType>::iterator sait;
		unsigned int lastActivityMaxLen = 13;
		unsigned int activityCountMaxLen = 1;
		unsigned int activityScoreMaxLen = 1;
		unsigned int refusedCountMaxLen = 1;
		unsigned int tmp = 0;
		std::time_t currentRawTime;
		std::time(&currentRawTime);
		unsigned long long int currentTime = (unsigned long long int)currentRawTime;
		// Find max for padding
		for (sait = this->suspiciousAddresses.begin(); sait!=this->suspiciousAddresses.end(); ++sait) {
			if (tmp == 0) {
				tmp = Util::formatDateTime((const time_t)sait->second.lastActivity, this->config->dateTimeFormat.c_str()).length();
				if (tmp > lastActivityMaxLen) lastActivityMaxLen = tmp;
			}
			tmp = std::to_string(sait->second.activityCount).length();
			if (tmp > activityCountMaxLen) activityCountMaxLen = tmp;
			tmp = std::to_string(sait->second.activityScore).length();
			if (tmp > activityScoreMaxLen) activityScoreMaxLen = tmp;
			tmp = std::to_string(sait->second.refusedCount).length();
			if (tmp > refusedCountMaxLen) refusedCountMaxLen = tmp;
		}
		// Output all blockecd addresses
		for (sait = this->suspiciousAddresses.begin(); sait!=this->suspiciousAddresses.end(); ++sait) {
			// Whitelisted addresses are not blocked
			if (sait->second.whitelisted && all == false) {
				continue;
			}
			if (sait->second.blacklisted
				|| (this->config->keepBlockedScoreMultiplier > 0 && currentTime < (sait->second.lastActivity + sait->second.activityScore) - (this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier))
				|| (this->config->keepBlockedScoreMultiplier == 0 && sait->second.activityScore > this->config->activityScoreToBlock)
				|| all) {
				std::cout << std::left << std::setw(15) << sait->first;
				if (count) {
					std::cout << ' ' << std::left << std::setw(activityCountMaxLen) << sait->second.activityCount;
					std::cout << ' ' << std::left << std::setw(activityScoreMaxLen) << sait->second.activityScore;
					std::cout << ' ' << std::left << std::setw(refusedCountMaxLen) << sait->second.refusedCount;
				}
				if (time) {
					std::cout << ' ' << Util::formatDateTime((const time_t)sait->second.lastActivity, this->config->dateTimeFormat.c_str());
				}
				std::cout << std::endl;
			}
		}
	} else {
		std::cout << "No data!" << std::endl;
	}
}
