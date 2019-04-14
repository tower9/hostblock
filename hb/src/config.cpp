/*
 * Class to work with hostblock config file.
 */

// Standard input/output stream library (cin, cout, cerr, clog, etc)
#include <iostream>
// Standard string library
#include <string>
// File stream library (ifstream)
#include <fstream>
// Time library (time_t, time, localtime)
#include <time.h>
// Logger
#include "logger.h"
// Util
#include "util.h"
// Header
#include "config.h"
// Syslog
namespace csyslog{
	#include <syslog.h>
}
// Linux stat
namespace cstat{
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
}

// Hostblock namespace
using namespace hb;

/*
 * Constructor
 */
Config::Config(hb::Logger* log)
: log(log)
{

}
Config::Config(hb::Logger* log, std::string configPath)
: log(log), configPath(configPath)
{

}

/*
 * Load configuration from file
 */
bool Config::load()
{
	this->log->debug("Loading config from " + this->configPath);
	std::ifstream f(this->configPath);
	if (f.is_open()) {
		std::string line;
		int group = 0;// 0 Global group, 1 Log group
		std::vector<hb::LogGroup>::iterator itlg;
		std::vector<hb::Pattern>::iterator itp;
		std::size_t pos, posip, posd;
		bool logDetails = true;
		struct cstat::stat buffer;
		unsigned int category = 0;
		std::string categoriesS = "";

		try{
			std::smatch groupSearchResults;
			std::regex groupSearchPattern("\\[\\S+\\]");

			// Clear log groups and files
			for (itlg = this->logGroups.begin(); itlg != this->logGroups.end(); ++itlg) {
				itlg->logFiles.clear();
				itlg->patterns.clear();
			}
			this->logGroups.clear();

			// Reset log group iterator
			itlg = this->logGroups.begin();

			// Read config file line by line
			while (std::getline(f, line)) {

				// Trim spaces from line
				line = hb::Util::rtrim(hb::Util::ltrim(line));

				// Skip lines that start with # (comments)
				if (line.length() > 0 && line[0] != '#') {

					// Remove comment if it is on same line
					pos = line.find_first_of("#");
					if (pos != std::string::npos) {
						line = hb::Util::rtrim(line.substr(0, pos - 1));
					}

					// Group handling - Gobal and Log.*
					if (std::regex_search(line, groupSearchResults, groupSearchPattern) && groupSearchResults.size() == 1) {
						if (line.substr(1, 6) == "Global") {
							group = 0;
						} else if (line.substr(1, 4) == "Log.") {
							group = 1;
							hb::LogGroup logGroup;
							logGroup.name = line.substr(5, line.length() - 6);
							if (logDetails) this->log->debug("Log file group: " + logGroup.name);
							itlg = this->logGroups.insert(this->logGroups.end(), logGroup);
						}
					}

					if (group == 0) {// Global section
						if (line.substr(0, 9) == "log.level") {
							pos = line.find_first_of('=');
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								if (line == "ERROR") {
									this->logLevel = "ERROR";
									this->log->setLevel(LOG_ERR);
								} else if (line == "WARNING") {
									this->logLevel = "WARNING";
									this->log->setLevel(LOG_WARNING);
								} else if (line == "INFO") {
									this->logLevel = "INFO";
									this->log->setLevel(LOG_INFO);
								} else if (line == "DEBUG") {
									this->logLevel = "DEBUG";
									this->log->setLevel(LOG_DEBUG);
								}
								if (logDetails) this->log->debug("Log level: " + line);
							}
						} else if (line.substr(0, 18) == "log.check.interval") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->logCheckInterval = strtoul(line.c_str(), NULL, 10);
								if (logDetails) this->log->debug("Interval for log file check: " + std::to_string(this->logCheckInterval));
							}
						} else if (line.substr(0, 19) == "address.block.score") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->activityScoreToBlock = strtoul(line.c_str(), NULL, 10);
								if (logDetails) this->log->debug("Needed score to block IP address: " + std::to_string(this->activityScoreToBlock));
							}
						} else if (line.substr(0, 24) == "address.block.multiplier") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->keepBlockedScoreMultiplier = strtoul(line.c_str(), NULL, 10);
								if (logDetails) this->log->debug("Score multiplier for rule keeping: " + std::to_string(this->keepBlockedScoreMultiplier));
							}
						} else if (line.substr(0, 20) == "iptables.rules.block") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								posip = line.find("%i");
								if (posip != std::string::npos) {
									this->iptablesRule = line;
									if (logDetails) this->log->debug("Iptables rule to drop packets: " + this->iptablesRule);
								} else {
									this->log->error("Failed to parse iptables.rules.block, IP address placeholder not found! Will use default value.");
								}
							}
						} else if (line.substr(0, 15) == "datetime.format") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->dateTimeFormat = line;
								if (logDetails) this->log->debug("Datetime format: " + this->dateTimeFormat);
							}
						} else if (line.substr(0, 13) == "datafile.path") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								this->dataFilePath = hb::Util::ltrim(line.substr(pos + 1));
								if (logDetails) this->log->debug("Datafile path: " + this->dataFilePath);
							}
						} else if (line.substr(0, 17) == "abuseipdb.api.url") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								this->abuseipdbURL = hb::Util::ltrim(line.substr(pos + 1));
								if (logDetails) this->log->debug("AbuseIPDB API URL: " + this->abuseipdbURL);
							}
						} else if (line.substr(0, 17) == "abuseipdb.api.key") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								this->abuseipdbKey = hb::Util::ltrim(line.substr(pos + 1));
								if (logDetails) this->log->debug("AbuseIPDB API key: " + this->abuseipdbKey);
							}
						} else if (line.substr(0, 25) == "abuseipdb.datetime.format") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->abuseipdbDatetimeFormat = line;
								if (logDetails) this->log->debug("AbuseIPDB API datetime format: " + this->abuseipdbDatetimeFormat);
							}
						} else if (line.substr(0, 28) == "abuseipdb.blacklist.interval") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->abuseipdbBlacklistInterval = strtoul(line.c_str(), NULL, 10);
								if (logDetails) this->log->debug("AbuseIPDB blacklist sync interval: " + std::to_string(this->abuseipdbBlacklistInterval));
							}
						} else if (line.substr(0, 21) == "abuseipdb.block.score") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->abuseipdbBlockScore = strtoul(line.c_str(), NULL, 10);
								if (this->abuseipdbBlockScore < 25) {
									this->abuseipdbBlockScore = 25;
								} else if (this->abuseipdbBlockScore > 100) {
									this->abuseipdbBlockScore = 100;
								}
								if (logDetails) this->log->debug("Needed AbuseIPDB confidence score to block address: " + std::to_string(this->abuseipdbBlockScore));
							}
						} else if (line.substr(0, 20) == "abuseipdb.report.all") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::toLower(hb::Util::ltrim(line.substr(pos + 1)));
								if (line == "true") {
									this->abuseipdbReportAll = true;
								} else {
									this->abuseipdbReportAll = false;
								}
								if (logDetails) this->log->debug("Report all matches to AbuseIPDB: " + std::to_string(this->abuseipdbReportAll));
							}
						} else if (line.substr(0, 21) == "abuseipdb.report.mask") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::toLower(hb::Util::ltrim(line.substr(pos + 1)));
								if (line == "true") {
									this->abuseipdbReportMask = true;
								} else {
									this->abuseipdbReportMask = false;
								}
								if (logDetails) this->log->debug("Mask comment before sending report to AbuseIPDB: " + std::to_string(this->abuseipdbReportMask));
							}
						} else if (line.substr(0, 27) == "abuseipdb.report.categories") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->abuseipdbDefaultCategories.clear();
								if (line.size() > 0) {
									try {
										if (logDetails) categoriesS = "";
										// Loop delimiters
										while ((posd = line.find(",")) != std::string::npos) {
											category = std::stoul(hb::Util::ltrim(line.substr(0, posd)));
											if (logDetails) categoriesS += std::to_string(category) + ", ";
											line.erase(0, posd + 1);// position + delimiter length
											this->abuseipdbDefaultCategories.insert(this->abuseipdbDefaultCategories.end(), category);
										}
										// And last one
										category = std::stoul(hb::Util::ltrim(line.substr(0, posd)));
										if (logDetails) {
											categoriesS += std::to_string(category);
											this->log->debug("AbuseIPDB API default categories for reporting: " + categoriesS);
										}
										this->abuseipdbDefaultCategories.insert(this->abuseipdbDefaultCategories.end(), category);
									} catch (std::invalid_argument& e) {
										this->log->error("Failed to parse AbuseIPDB API default categories! Failed to parse value!");
									} catch (std::out_of_range& e) {
										this->log->error("Failed to parse AbuseIPDB API default categories! Failed to parse value (out of range)!");
									}
								} else {
									this->log->error("Failed to parse AbuseIPDB API default categories! Empty value!");
								}
							}
						} else if (line.substr(0, 24) == "abuseipdb.report.comment") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								this->abuseipdbDefaultComment = line;
								this->abuseipdbDefaultCommentIsSet = true;
								if (logDetails) this->log->debug("AbuseIPDB API default comment for reporting: " + this->abuseipdbDefaultComment);
							}
						}
					} else if (group == 1) {// Log group section
						if (line.substr(0, 20) == "abuseipdb.report.all") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::toLower(hb::Util::ltrim(line.substr(pos + 1)));
								if (line == "true") {
									itlg->abuseipdbReport = Report::True;
								} else if (line == "false") {
									itlg->abuseipdbReport = Report::False;
								} else {
									itlg->abuseipdbReport = Report::NotSet;
								}
								if (logDetails) this->log->debug("Log group reporting to AbuseIPDB: " + std::to_string(itlg->abuseipdbReport));
							}
						} else if (line.substr(0, 27) == "abuseipdb.report.categories") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								if (line.size() > 0) {
									try {
										if (logDetails) categoriesS = "";
										// Loop delimiters
										while ((posd = line.find(",")) != std::string::npos) {
											category = std::stoul(hb::Util::ltrim(line.substr(0, posd)));
											if (logDetails) categoriesS += std::to_string(category) + ", ";
											line.erase(0, posd + 1);// position + delimiter length
											itlg->abuseipdbCategories.insert(itlg->abuseipdbCategories.end(), category);
										}
										// And last one
										category = std::stoul(hb::Util::ltrim(line.substr(0, posd)));
										if (logDetails) {
											categoriesS += std::to_string(category);
											this->log->debug("Log group AbuseIPDB categories for reporting: " + categoriesS);
										}
										itlg->abuseipdbCategories.insert(itlg->abuseipdbCategories.end(), category);
									} catch (std::invalid_argument& e) {
										this->log->error("Failed to parse log group AbuseIPDB categories! Failed to parse value!");
									} catch (std::out_of_range& e) {
										this->log->error("Failed to parse log group AbuseIPDB categories! Failed to parse value (out of range)!");
									}
								} else {
									this->log->error("Failed to parse log group AbuseIPDB categories! Empty value!");
								}
							}
						} else if (line.substr(0, 24) == "abuseipdb.report.comment") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								itlg->abuseipdbComment = line;
								itlg->abuseipdbCommentIsSet = true;
								if (logDetails) this->log->debug("Log group AbuseIPDB comment for reporting: " + itlg->abuseipdbComment);
							}
						} else if (line.substr(0, 8) == "log.path") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								hb::LogFile logFile;
								logFile.path = hb::Util::ltrim(line.substr(pos + 1));
								if (cstat::stat(logFile.path.c_str(), &buffer) != 0) {
									this->log->warning("Log file found in configuration, but not found in file system! Path: " + logFile.path);
								}
								itlg->logFiles.push_back(logFile);
								if (logDetails) this->log->debug("Logfile path: " + hb::Util::ltrim(line.substr(pos+1)));
							}
						} else if (line.substr(0, 11) == "log.pattern") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								hb::Pattern pattern;
								pattern.patternString = hb::Util::ltrim(line.substr(pos + 1));
								// Pattern must contain %i, a placeholder to find IP address
								posip = pattern.patternString.find("%i");
								if (posip != std::string::npos) {
									itp = itlg->patterns.end();
									itp = itlg->patterns.insert(itp, pattern);
									if (logDetails) this->log->debug("Pattern to match: " + pattern.patternString);
								} else {
									this->log->warning("Unable to find \%i in pattern, pattern skipped: " + pattern.patternString);
								}
							}
						} else if (line.substr(0, 9) == "log.score") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								itp->score = strtoul(line.c_str(), NULL, 10);
								if (logDetails) this->log->debug("Score for previous pattern: " + std::to_string(itp->score));
							}
						} else if (line.substr(0, 19) == "log.refused.pattern") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								hb::Pattern pattern;
								pattern.patternString = hb::Util::ltrim(line.substr(pos + 1));
								// Pattern must contain %i, which is placeholder for where to find IP address
								posip = pattern.patternString.find("%i");
								if (posip != std::string::npos) {
									itp = itlg->refusedPatterns.end();
									itp = itlg->refusedPatterns.insert(itp, pattern);
									if (logDetails) this->log->debug("Pattern to match blocked access: " + pattern.patternString);
								} else {
									this->log->warning("Unable to find \%i in pattern, pattern skipped: " + pattern.patternString);
								}
							}
						} else if (line.substr(0, 17) == "log.refused.score") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								itp->score = strtoul(line.c_str(), NULL, 10);
								if (logDetails) this->log->debug("Score for previous pattern: " + std::to_string(itp->score));
							}
						} else if (line.substr(0, 20) == "log.abuseipdb.report") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::toLower(hb::Util::ltrim(line.substr(pos + 1)));
								if (line == "true") {
									itp->abuseipdbReport = Report::True;
								} else if (line == "false") {
									itp->abuseipdbReport = Report::False;
								} else {
									itp->abuseipdbReport = Report::NotSet;
								}
								if (logDetails) this->log->debug("Log pattern reporting to AbuseIPDB: " + std::to_string(itp->abuseipdbReport));
							}
						} else if (line.substr(0, 24) == "log.abuseipdb.categories") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								if (line.size() > 0) {
									try {
										if (logDetails) categoriesS = "";
										// Loop delimiters
										while ((posd = line.find(",")) != std::string::npos) {
											category = std::stoul(hb::Util::ltrim(line.substr(0, posd)));
											if (logDetails) categoriesS += std::to_string(category) + ", ";
											line.erase(0, posd + 1);// position + delimiter length
											itp->abuseipdbCategories.insert(itp->abuseipdbCategories.end(), category);
										}
										// And last one
										category = std::stoul(hb::Util::ltrim(line.substr(0, posd)));
										if (logDetails) {
											categoriesS += std::to_string(category);
											this->log->debug("Log pattern AbuseIPDB categories for reporting: " + categoriesS);
										}
										itp->abuseipdbCategories.insert(itp->abuseipdbCategories.end(), category);
									} catch (std::invalid_argument& e) {
										this->log->error("Failed to parse log pattern AbuseIPDB categories! Failed to parse value!");
									} catch (std::out_of_range& e) {
										this->log->error("Failed to parse log pattern AbuseIPDB categories! Failed to parse value (out of range)!");
									}
								} else {
									this->log->error("Failed to parse log pattern AbuseIPDB categories! Empty value!");
								}
							}
						} else if (line.substr(0, 21) == "log.abuseipdb.comment") {
							pos = line.find_first_of("=");
							if (pos != std::string::npos) {
								line = hb::Util::ltrim(line.substr(pos + 1));
								itp->abuseipdbComment = line;
								itp->abuseipdbCommentIsSet = true;
								if (logDetails) this->log->debug("Log pattern AbuseIPDB comment for reporting: " + itp->abuseipdbComment);
							}
						}

					}
				}
			}
		} catch (std::regex_error& e){
			std::string message = e.what();
			this->log->error(message + ": " + std::to_string(e.code()));
			this->log->error(Util::regexErrorCode2Text(e.code()));
			return false;
		}
	} else {
		std::string message = "Failed to open configuration file!";
		message += " " + std::to_string(errno) + ": " + strerror(errno);
		throw std::runtime_error(message);
	}
	return true;
}

/*
 * Process patterns
 * std::string patternString -> std::regex pattern
 */
bool Config::processPatterns()
{
	std::vector<LogGroup>::iterator itlg;
	std::vector<Pattern>::iterator itpa;
	std::size_t posip, posport;
	try{
		for (itlg = this->logGroups.begin(); itlg != this->logGroups.end(); ++itlg) {
			for (itpa = itlg->patterns.begin(); itpa != itlg->patterns.end(); ++itpa) {
				posip = itpa->patternString.find("%i");
				posport = itpa->patternString.find("%p");
				if (posip != std::string::npos) {
					if (posport != std::string::npos) {
						itpa->patternString.replace(posport, 2, "(\\d{1,5})");
						itpa->portSearch = true;
					}
					itpa->pattern = std::regex(itpa->patternString.replace(posip, 2, "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"), std::regex_constants::icase);
					// std::cout << "Regex pattern: " << itpa->patternString << std::endl;
				} else {
					this->log->error("Unable to find ip address placeholder \%i in pattern, failed to parse pattern: " + itpa->patternString);
					return false;
				}
			}
			for (itpa = itlg->refusedPatterns.begin(); itpa != itlg->refusedPatterns.end(); ++itpa) {
				posip = itpa->patternString.find("%i");
				posport = itpa->patternString.find("%p");
				if (posip != std::string::npos) {
					if (posport != std::string::npos) {
						itpa->patternString.replace(posport, 2, "(\\d{1,5})");
						itpa->portSearch = true;
					}
					itpa->pattern = std::regex(itpa->patternString.replace(posip, 2, "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"), std::regex_constants::icase);
					// std::cout << "Regex pattern: " << itpa->patternString << std::endl;
				} else {
					this->log->error("Unable to find ip address placeholder \%i in pattern, failed to parse pattern: " + itpa->patternString);
					return false;
				}
			}
		}
	} catch (std::regex_error& e){
		std::string message = e.what();
		this->log->error(message + ": " + std::to_string(e.code()));
		this->log->error(Util::regexErrorCode2Text(e.code()));
		return false;
	}
	return true;
}

/*
 * Print (stdout) currently loaded config
 */
void Config::print()
{
	time_t currentTime;
	time(&currentTime);
	std::cout << "## Automatically generated Hostblock configuration" << std::endl;
	std::cout << "## Timestamp: " << currentTime << std::endl << std::endl;
	std::cout << "[Global]" << std::endl << std::endl;
	std::cout << "## Log level (ERROR/WARNING/INFO/DEBUG)" << std::endl;
	std::cout << "## ERROR - write only error messages to syslog" << std::endl;
	std::cout << "## WARNING - write error and warning messages to syslog" << std::endl;
	std::cout << "## INFO - write error, warning and info messages to syslog (default)" << std::endl;
	std::cout << "## DEBUG - write all messages to syslog" << std::endl;
	std::cout << "log.level = " << this->logLevel << std::endl << std::endl;
	std::cout << "## Interval for log file check (seconds, default 30)" << std::endl;
	std::cout << "log.check.interval = " << this->logCheckInterval << std::endl << std::endl;
	std::cout << "Needed score to create iptables rule for IP address connection drop (default 10)" << std::endl;
	std::cout << "address.block.score = " << this->activityScoreToBlock << std::endl << std::endl;
	std::cout << "## Score multiplier to calculate time how long iptables rule should be kept (seconds, default 3600, 0 will not remove automatically)" << std::endl;
	std::cout << "address.block.multiplier = " << this->keepBlockedScoreMultiplier << std::endl << std::endl;
	std::cout << "## Rule to use in IP tables rule (use %i as placeholder to specify IP address)" << std::endl;
	std::cout << "iptables.rules.block = " << this->iptablesRule << std::endl << std::endl;
	std::cout << "## Datetime format (default %Y-%m-%d %H:%M:%S)" << std::endl;
	std::cout << "datetime.format = " << this->dateTimeFormat << std::endl << std::endl;
	std::cout << "## Datafile location" << std::endl;
	std::cout << "datafile.path = " << this->dataFilePath << std::endl << std::endl;
	std::cout << "## AbuseIPDB URL" << std::endl;
	std::cout << "abuseipdb.api.url = " << this->abuseipdbURL << std::endl << std::endl;
	std::vector<unsigned int>::iterator itc;// AbuseipDB category iterator
	if (this->abuseipdbKey.size() > 0) {
		std::cout << "## AbuseIPDB API Key" << std::endl;
		std::cout << "abuseipdb.api.key = " << this->abuseipdbKey << std::endl << std::endl;
		if (this->abuseipdbDatetimeFormat.size() > 0) {
			std::cout << "## AbuseIPDB API date time format" << std::endl;
			std::cout << "abuseipdb.datetime.format = " << this->abuseipdbDatetimeFormat << std::endl << std::endl;
		}
		std::cout << "## Interval to sync AbuseIPDB blacklist, use 0 to disable (seconds, default 0)" << std::endl;
		std::cout << "## Note, it is recommended to sync no more often than once per 24h, i.e. 86400 seconds" << std::endl;
		std::cout << "abuseipdb.blacklist.interval = " << this->abuseipdbBlacklistInterval << std::endl << std::endl;
		std::cout << "## AbuseIPDB min score to block IP address (25 to 100, default 90)" << std::endl;
		std::cout << "##  If AbuseIPDB confidence score is >= than this setting, then iptables rule to block is created (also used for blacklist sync)" << std::endl;
		std::cout << "## It is recommended to use value between 75 and 100" << std::endl;
		std::cout << "## Note, 25 is minimum allowed by AbuseIPDB blacklist API" << std::endl;
		std::cout << "abuseipdb.block.score = " << this->abuseipdbBlockScore << std::endl << std::endl;
		std::cout << "## Whether to report all matches to AbuseIPDB (true|false, default false)" << std::endl;
		std::cout << "abuseipdb.report.all = ";
		if (this->abuseipdbReportAll == true) {
			std::cout << "true";
		} else {
			std::cout << "false";
		}
		std::cout << std::endl << std::endl;
		std::cout << "## Mask hostname before sending report to AbuseIPDB (true|false, default true)" << std::endl;
		std::cout << "abuseipdb.report.mask = ";
		if (this->abuseipdbReportMask == true) {
			std::cout << "true";
		} else {
			std::cout << "false";
		}
		std::cout << std::endl << std::endl;
		if (this->abuseipdbDefaultCategories.size() > 0) {
			std::cout << "## Default categories for reporting to AbuseIPDB (default 15, separated with comma, must have at least one category)" << std::endl;
			std::cout << "abuseipdb.report.categories = ";
			itc = this->abuseipdbDefaultCategories.begin();
			std::cout << *itc;
			++itc;
			for (; itc != this->abuseipdbDefaultCategories.end(); ++itc) {
				std::cout << "," << *itc;
			}
			std::cout << std::endl << std::endl;
		}
		if (this->abuseipdbDefaultCommentIsSet) {
			std::cout << "## Default comment for AbuseIPDB reports" << std::endl;
			std::cout << "## Use %m to include matched line" << std::endl;
			std::cout << "## Use %i to include address" << std::endl;
			std::cout << "abuseipdb.report.comment = " << this->abuseipdbDefaultComment << std::endl << std::endl;
		}
	}
	std::vector<LogGroup>::iterator itlg;
	std::vector<LogFile>::iterator itlf;
	std::vector<Pattern>::iterator itpa;
	for (itlg = this->logGroups.begin(); itlg != this->logGroups.end(); ++itlg) {
		std::cout << std::endl << "## Pattern and log file configuration for " << itlg->name << std::endl;
		std::cout << "[Log." << itlg->name << "]" << std::endl << std::endl;
		if (this->abuseipdbKey.size() > 0) {
			std::cout << "## AbuseIPDB log group level configuration (overrides global settings)" << std::endl;
			if (itlg->abuseipdbReport != Report::NotSet) {
				std::cout << "abuseipdb.report.all = ";
				if (itlg->abuseipdbReport == Report::True) {
					std::cout << "true";
				} else {
					std::cout << "false";
				}
				std::cout << std::endl;
			}
			if (itlg->abuseipdbCategories.size() > 0) {
      	std::cout << "abuseipdb.report.categories = ";
				itc = itlg->abuseipdbCategories.begin();
				std::cout << *itc;
				++itc;
				for (; itc != itlg->abuseipdbCategories.end(); ++itc) {
					std::cout << "," << *itc;
				}
				std::cout << std::endl;
			}
			if (itlg->abuseipdbCommentIsSet) {
				std::cout << "abuseipdb.report.comment = " << itlg->abuseipdbComment << std::endl;
			}
			std::cout << std::endl;
		}
		std::cout << "## Full path to log file(s)" << std::endl;
		for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
			std::cout << "log.path = " << itlf->path << std::endl << std::endl;
		}
		if (itlg->patterns.size() > 0) {
			std::cout << "## Patterns to match with scores to use for calculation" << std::endl;
			std::cout << "## Use %i to specify where in pattern IP address should be looked for" << std::endl;
			std::cout << "## Score must follow after pattern, if not specified by default will be set 1" << std::endl;
			for (itpa = itlg->patterns.begin(); itpa != itlg->patterns.end(); ++itpa) {
				std::cout << "log.pattern = " << itpa->patternString << std::endl;
				if (itpa->score > 1) {
					std::cout << "log.score = " << itpa->score << std::endl;
				}
				if (itpa->abuseipdbReport != Report::NotSet) {
					std::cout << "log.abuseipdb.report = ";
					if (itpa->abuseipdbReport == Report::True) {
						std::cout << "true";
					} else {
						std::cout << "false";
					}
					std::cout << std::endl;
				}
				if (itpa->abuseipdbCategories.size() > 0) {
					std::cout << "log.abuseipdb.categories = ";
					itc = itpa->abuseipdbCategories.begin();
					std::cout << *itc;
					++itc;
					for (; itc != itpa->abuseipdbCategories.end(); ++itc) {
						std::cout << "," << *itc;
					}
					std::cout << std::endl;
				}
				if (itpa->abuseipdbCommentIsSet) {
					std::cout << "log.abuseipdb.comment = " << itpa->abuseipdbComment << std::endl;
				}
				std::cout << std::endl;
			}
		}
		if (itlg->refusedPatterns.size() > 0) {
			std::cout << "## Patterns in log file to count refused connection count" << std::endl;
			std::cout << "## Include %i in pattern, will search there for IP address" << std::endl;
			std::cout << "## Specify score after each pattern, if not specified by default will be set 1" << std::endl;
			for (itpa = itlg->refusedPatterns.begin(); itpa != itlg->refusedPatterns.end(); ++itpa) {
				std::cout << "log.refused.pattern = " << itpa->patternString << std::endl;
				if (itpa->score > 1) {
					std::cout << "log.refused.score = " << itpa->score << std::endl;
				}
				if (itpa->abuseipdbReport != Report::NotSet) {
					std::cout << "log.abuseipdb.report = ";
					if (itpa->abuseipdbReport == Report::True) {
						std::cout << "true";
					} else {
						std::cout << "false";
					}
					std::cout << std::endl;
				}
				if (itpa->abuseipdbCategories.size() > 0) {
					std::cout << "log.abuseipdb.categories = ";
					itc = itpa->abuseipdbCategories.begin();
					std::cout << *itc;
					++itc;
					for (; itc != itpa->abuseipdbCategories.end(); ++itc) {
						std::cout << "," << *itc;
					}
					std::cout << std::endl;
				}
				if (itpa->abuseipdbCommentIsSet) {
					std::cout << "log.abuseipdb.comment = " << itpa->abuseipdbComment << std::endl;
				}
				std::cout << std::endl;
			}
		}
	}
}
