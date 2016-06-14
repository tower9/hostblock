/*
 * Log file parser, match patterns with lines in log files
 * 
 * Some notes, seems that std regex is slower than boost version, maybe worth a switch...
 */

// Standard input/output stream library (cin, cout, cerr, clog)
#include <iostream>
// File stream library (ifstream)
#include <fstream>
// C string
#include <cstring>
// Miscellaneous UNIX symbolic constants, types and functions
namespace cunistd{
	#include <unistd.h>
}
// Linux stat
namespace cstat{
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
}
// Util
#include "util.h"
// Header
#include "logparser.h"

// Hostblock namespace
using namespace hb;

/*
 * Constructor
 */
LogParser::LogParser(hb::Logger* log, hb::Config* config, hb::Iptables* iptables, hb::Data* data)
: log(log), config(config), iptables(iptables), data(data)
{

}

/*
 * Check all configured log files for suspicious activity
 */
void LogParser::checkFiles()
{
	this->log->debug("Checking log files for suspicious activity...");
	std::vector<hb::LogGroup>::iterator itlg;
	std::vector<hb::LogFile>::iterator itlf;
	std::vector<hb::Pattern>::iterator itlp;
	struct cstat::stat buffer;
	unsigned long long int fileSize = 0;
	unsigned long long int initialBookmark = 0;
	std::string line;
	std::string ipAddress;
	std::regex ipSearchPattern("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
	std::smatch ipSearchResults;
	time_t currentTime, lastInfo;
	time(&currentTime);
	lastInfo = currentTime;
	unsigned long long int jobTotal = 0, jobDone = 0;
	float jobPercentage = 0;

	// Loop log groups
	for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
		this->log->debug("Checking log group: " + itlg->name);

		// Loop log files in each group
		for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
			this->log->debug("Checking log file: " + itlf->path);

			// Simple log rotation check (based on file size change)
			if (cstat::stat(itlf->path.c_str(), &buffer) == 0) {
				fileSize = (intmax_t)buffer.st_size;
				if (fileSize < itlf->size) {
					itlf->bookmark = 0;
					this->log->warning("Last known size reset for " + itlf->path);
				}
				this->log->debug("Current size: " + std::to_string(fileSize) + " Last known size: " + std::to_string(itlf->size));
			} else {
				this->log->error("Unable to open file " + itlf->path + "! " + std::to_string(errno) + ": " + std::string(strerror(errno)));
				continue;
			}

			// Check log file
			std::ifstream is(itlf->path, std::ifstream::binary);
			if (is && is.is_open()) {
				// Seek to last known position
				is.seekg(itlf->bookmark, is.beg);

				// For comparision after log check to see if bookmark has changed and datafile needs to be updated
				initialBookmark = itlf->bookmark;

				// Calculate total job to do
				jobTotal = fileSize - initialBookmark;

				// Read new lines until end of file
				while (std::getline(is, line)) {

					// Match patterns
					for (itlp = itlg->patterns.begin(); itlp != itlg->patterns.end(); ++itlp) {
						try {

							// Match line with pattern
							if (std::regex_match(line, itlp->pattern)) {

								// Get IP address out of line
								if (std::regex_search(line, ipSearchResults, ipSearchPattern)) {
									if (ipSearchResults.size() > 0) {

										// Optmistically here we think that first match is address we need
										ipAddress = std::string(ipSearchResults[0]);
										this->log->debug("Pattern match! Address: " + ipAddress + " Score: " + std::to_string(itlp->score));

										// Update address data
										this->saveActivity(ipAddress, itlp->score, 1, 0);
									}
								} 
								// this->log->debug("Line: " + line);
								this->log->debug("Pattern: " + itlp->patternString);
							}
						} catch (std::regex_error& e) {
							std::string message = e.what();
							this->log->error(message + ": " + std::to_string(e.code()));
							this->log->error(hb::Util::regexErrorCode2Text(e.code()));
						}
					}

					// Update bookmark
					itlf->bookmark = is.tellg();

					// Sleep
					cunistd::usleep(500);

					// Output some info to log file each min
					time(&currentTime);
					if (currentTime - lastInfo >= 60) {
						jobDone = itlf->bookmark - initialBookmark;
						jobPercentage = (float)jobDone * 100 / (float)jobTotal;
						this->log->info("Processing " + itlf->path + ", progress: " + std::to_string(jobPercentage) + "%");
						lastInfo = currentTime;
					}
				}
				this->log->debug("Finished reading until end of file, pos: " + std::to_string(itlf->bookmark));

				// Close file
				is.close();

				// Update last known file size
				itlf->size = fileSize;

				// Update datafile
				if (initialBookmark != itlf->bookmark) {
					this->data->updateFile(itlf->path);
				}
			} else {
				this->log->error("Unable to open file " + itlf->path + " for reading!");
				continue;
			}

		}
	}
}


/*
 * Save suspicious activity to data->suspiciousAddreses and datafile
 */
void LogParser::saveActivity(std::string address, unsigned int activityScore, unsigned int activityCount, unsigned int refusedCount)
{
	std::time_t currentTime;
	std::time(&currentTime);

	// Warning if only last activity time changes
	if (activityScore == 0 && activityCount == 0 && refusedCount == 0) {
		this->log->warning("Trying to register activity, but no data about activity! Only last activity time for address " + address + " will be updated!");
	}

	// Check if new record needs to be added or we need to update existing data
	bool newEntry = false;
	if (this->data->suspiciousAddresses.count(address) > 0) {

		// This address already had some activity previously, need to recalculate score
		this->log->debug("Previous activity: " + std::to_string(this->data->suspiciousAddresses[address].lastActivity));
		
		// Adjust score according to time passed
		if (this->config->keepBlockedScoreMultiplier > 0 && this->data->suspiciousAddresses[address].activityScore > 0) {
			this->log->debug("Adjusting previous score according to time passed...");
			if (this->data->suspiciousAddresses[address].activityScore < currentTime - this->data->suspiciousAddresses[address].lastActivity) {
				this->data->suspiciousAddresses[address].activityScore = 0;
			} else {
				this->data->suspiciousAddresses[address].activityScore -= currentTime - this->data->suspiciousAddresses[address].lastActivity;
			}
		}
		this->data->suspiciousAddresses[address].lastActivity = (unsigned long long int)currentTime;
		
		// Use score multiplier
		if (this->config->keepBlockedScoreMultiplier > 0) {
			this->log->debug("Adjusting new score according to multiplier...");
			activityScore = activityScore * this->config->keepBlockedScoreMultiplier;
		}
		this->data->suspiciousAddresses[address].activityScore += activityScore;
		this->data->suspiciousAddresses[address].activityCount += activityCount;
		this->data->suspiciousAddresses[address].refusedCount += refusedCount;

	} else {

		// First time activity from this address
		SuspiciosAddressType data;
		data.lastActivity = (unsigned long long int)currentTime;
		if (this->config->keepBlockedScoreMultiplier > 0) {
			data.activityScore = activityScore*this->config->keepBlockedScoreMultiplier;
		} else {
			data.activityScore = activityScore;
		}
		if (activityScore > 0) data.activityCount = activityCount;
		data.refusedCount = refusedCount;
		data.whitelisted = false;
		data.blacklisted = false;
		this->data->suspiciousAddresses.insert(std::pair<std::string,SuspiciosAddressType>(address,data));
		newEntry = true;
	}

	// Few details for debug
	this->log->debug("Last activity: " + std::to_string(this->data->suspiciousAddresses[address].lastActivity));
	this->log->debug("Activity score: " + std::to_string(this->data->suspiciousAddresses[address].activityScore));
	this->log->debug("Activity count: " + std::to_string(this->data->suspiciousAddresses[address].activityCount));
	this->log->debug("Refused count: " + std::to_string(this->data->suspiciousAddresses[address].refusedCount));
	if (this->data->suspiciousAddresses[address].whitelisted) this->log->debug("Address is in whitelist!");
	if (this->data->suspiciousAddresses[address].blacklisted) this->log->debug("Address is in blacklist!");

	// Check new score and see if need to add to/remove from iptables
	bool createRule = false;
	bool removeRule = false;
	if (this->data->suspiciousAddresses[address].iptableRule) {// Rule exists, check if need to remove

		// Whitelisted addresses must not have rule
		if (this->data->suspiciousAddresses[address].whitelisted == true) {
			removeRule = true;
		}

		// Keep rule for blacklisted addresses
		if (this->data->suspiciousAddresses[address].blacklisted != true) {
			// Rule removal only when recalculated score reaches 0
			if (this->data->suspiciousAddresses[address].activityScore == 0) {
				removeRule = true;
			}
		}
	} else {// Rule does not exist, check if need to add

		// Blacklisted addresses must have rule
		if (this->data->suspiciousAddresses[address].blacklisted == true) {
			createRule = true;
		}

		// Whitelisted addresses must not have rule
		if (this->data->suspiciousAddresses[address].whitelisted != true) {

			// There are two modes for rule keeping in iptables
			if (this->config->keepBlockedScoreMultiplier > 0) {

				// Using score multiplier, recheck if score is enough to create rule, score is already recalculated
				if (this->data->suspiciousAddresses[address].activityScore > this->config->activityScoreToBlock * this->config->keepBlockedScoreMultiplier) {
					createRule = true;
				}

			} else{

				// Without multiplier rules are kept forever for cases where there is enough score
				if (this->data->suspiciousAddresses[address].activityScore > this->config->activityScoreToBlock) {
					createRule = true;
				}

			}
		}
	}

	// Adjust iptables rules
	if (createRule == true) {
		this->log->debug("Adding rule for " + address + " to iptables chain!");
		try {
			if (this->iptables->append("INPUT","-s " + address + " -j DROP") == false) {
				this->log->error("Address " + address + " has enough score now, should have iptables rule and hostblock failed to append rule to chain!");
			} else {
				this->data->suspiciousAddresses[address].iptableRule = true;
			}
		} catch (std::runtime_error& e) {
			std::string message = e.what();
			this->log->error(message);
			this->log->error("Address " + address + " has enough score now, should have iptables rule and hostblock failed to append rule to chain!");
		}
	}
	if(removeRule == true) {
		this->log->debug("Removing rule of " + address + " from iptables chain!");
		try {
			if(this->iptables->remove("INPUT","-s " + address + " -j DROP") == false){
				this->log->error("Address " + address + " no longer needs iptables rule, but failed to remove rule from chain!");
			} else {
				this->data->suspiciousAddresses[address].iptableRule = false;
			}
		} catch (std::runtime_error& e) {
			std::string message = e.what();
			this->log->error(message);
			this->log->error("Address " + address + " no longer needs iptables rule, but failed to remove rule from chain!");
		}
	}

	// Update data file
	if(newEntry == true){
		// Add new entry to end of data file
		this->data->addAddress(address);
	} else{
		// Update entry in data file
		this->data->updateAddress(address);
	}

}
