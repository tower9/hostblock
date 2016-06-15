/* 
 * Hostblock 2.0
 *
 * Automatic blocking of suspicious remote IP hosts - tool monitors log files
 * for suspicious activity to automatically deny further access.
 *
 * @author Rolands Kusiņš
 * @license GPL
 */

// Standard input/output stream library (cin, cout, cerr, clog)
#include <iostream>
// File stream library (ifstream)
#include <fstream>
// Miscellaneous UNIX symbolic constants, types and functions (fork)
namespace cunistd{
	#include <unistd.h>
}
// Signal handling
// #include <csignal>
// C signal handling
namespace csignal{
	#include <signal.h>
}
// C getopt
namespace cgetopt{
	#include <getopt.h>
}
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
// Logger
#include "logger.h"
// Iptables
#include "iptables.h"
// Config
#include "config.h"
// Data
#include "data.h"
// LogParser
#include "logparser.h"

// Full path to PID file
const char* PID_PATH = "/var/run/hostblock.pid";
// Variable for main loop, will exit when set to false
bool running = false;
// Variable for daemon to reload data file
bool reloadDataFile = false;
// Variable for daemon to reload configuration
bool reloadConfig = false;

/*
 * Output short help
 */
void printUsage()
{
	std::cout << "Hostblock v.2.0" << std::endl << std::endl;
	std::cout << "hostblock [-h | --help] [-s | --statistics] [-l | --list [-c | --count] [-t | --time]] [-r<ip_address> | --remove=<ip_address>] [-d | --daemon]" << std::endl << std::endl;
	std::cout << " -h             | --help                - this information" << std::endl;
	std::cout << " -s             | --statistics          - statistics" << std::endl;
	std::cout << " -l             | --list                - list of blocked suspicious IP addresses" << std::endl;
	std::cout << " -lc            | --list --count        - list of blocked suspicious IP addresses with suspicious activity count" << std::endl;
	std::cout << " -lt            | --list --time         - list of blocked suspicious IP addresses with last suspicious activity time" << std::endl;
	std::cout << " -lct           | --list --count --time - list of blocked suspicious IP addresses with suspicious activity count and last suspicious activity time" << std::endl;
	std::cout << " -r<IP address> | --remove=<IP address> - remove IP address from data file" << std::endl;
	std::cout << " -d             | --daemon              - run as daemon" << std::endl;
}

/*
 * Signal handler
 */
void signalHandler(int signal)
{
	if (signal == SIGTERM) {
		// Stop daemon
		running = false;
	} else if (signal == SIGUSR1) {
		// SIGUSR1 to tell daemon to reload data and config
		reloadDataFile = true;
		reloadConfig = true;
	}
}

/*
 * Main
 */
int main(int argc, char *argv[])
{
	clock_t initStart = clock(), initEnd;

	// Must have at least one argument
	if (argc < 2) {
		printUsage();
		exit(0);
	}

	// Var init
	int c;
	bool statisticsFlag = false;
	bool listFlag = false;
	bool countFlag = false;
	bool timeFlag = false;
	bool removeFlag = false;
	std::string removeAddress = "";
	bool daemonFlag = false;

	// Options
	static struct cgetopt::option long_options[] = 
	{
		{"help",       no_argument,       0, 'h'},
		{"statistics", no_argument,       0, 's'},
		{"list",       no_argument,       0, 'l'},
		{"count",      no_argument,       0, 'c'},
		{"time",       no_argument,       0, 't'},
		{"remove",     required_argument, 0, 'r'},
		{"daemon",     no_argument,       0, 'd'},
	};

	// Option index
	int option_index = 0;

	// Check options
	while ((c = cgetopt::getopt_long(argc, argv, "hslctr:d", long_options, &option_index)) != -1)
		switch (c) {
			case 'h':
				printUsage();
				exit(0);
				break;
			case 's':
				statisticsFlag = true;
				break;
			case 'l':
				listFlag = true;
				break;
			case 'c':
				countFlag = true;
				break;
			case 't':
				timeFlag = true;
				break;
			case 'r':
				removeFlag = true;
				removeAddress = cgetopt::optarg;
				break;
			case 'd':
				daemonFlag = true;
				break;
			default:
				printUsage();
				exit(0);
		}

	// Init writter to syslog
	hb::Logger log = hb::Logger(LOG_USER);

	// Init object to work with iptables
	hb::Iptables iptables = hb::Iptables();

	// Init config, default path to config file is /etc/hostblock.conf
	hb::Config config = hb::Config(&log, "/etc/hostblock.conf");

	// If env variable $HOSTBLOCK_CONFIG is set, then use value from it as path to config
	if (const char* env_cp = std::getenv("HOSTBLOCK_CONFIG")) {
		config.configPath = std::string(env_cp);
	}

	// Load config
	if (!config.load()) {
		std::cerr << "Failed to load configuration file!" << std::endl;
		exit(1);
	}

	// Init object to work with datafile
	hb::Data data = hb::Data(&log, &config, &iptables);

	// Load datafile
	if (!data.loadData()) {
		std::cerr << "Failed to load data!" << std::endl;
		exit(1);
	}

	if (statisticsFlag) {// Output statistics
		data.printStats();
		if (config.logLevel == "DEBUG") {
			initEnd = clock();
			log.debug("Statistics outputed in " + std::to_string((double)(initEnd - initStart)/CLOCKS_PER_SEC) + " sec");
		}
		exit(0);
	} else if (listFlag) {// Output list of blocked suspicious addresses

		if (config.logLevel == "DEBUG") {
			initEnd = clock();
			log.debug("List of blocked addresses outputed in " + std::to_string((double)(initEnd - initStart)/CLOCKS_PER_SEC) + " sec");
		}
		exit(0);
	} else if (removeFlag) {// Remove address from datafile

		if (config.logLevel == "DEBUG") {
			initEnd = clock();
			log.debug("Address removed in " + std::to_string((double)(initEnd - initStart)/CLOCKS_PER_SEC) + " sec");
		}
		exit(0);
	} else if (daemonFlag) {// Run as daemon
		// Reopen syslog
		log.closeLog();
		log.openLog(LOG_DAEMON);

		// Restore log level
		if (config.logLevel == "ERROR") {
			log.setLevel(LOG_ERR);
		} else if (config.logLevel == "WARNING") {
			log.setLevel(LOG_WARNING);
		} else if (config.logLevel == "INFO") {
			log.setLevel(LOG_INFO);
		} else if (config.logLevel == "DEBUG") {
			log.setLevel(LOG_DEBUG);
		}
		log.info("Starting daemon process...");

		// Check if file with PID exists
		struct cstat::stat buffer;
		if (cstat::stat(PID_PATH, &buffer) == 0) {
			// Get PID from file
			std::ifstream f(PID_PATH);
			if (f.is_open()){
				std::string line;
				std::getline(f, line);
				pid_t pid = (pid_t)strtoul(line.c_str(), NULL, 10);
				if (csignal::kill(pid, 0) == 0) {// Process exists and is running
					std::cerr << "Unable to start! Another instance of hostblock is already running!" << std::endl;
					log.error("Unable to start! Another instance of hostblock is already running!");
					exit(1);
				} else {// Process does not exist, remove pid file
					std::remove(PID_PATH);
				}
			} else {
				std::cerr << "Unable to start! Another instance of hostblock is already running!" << std::endl;
				log.error("Unable to start! Another instance of hostblock is already running!");
				exit(1);
			}
		}

		pid_t pid;
		pid = cunistd::fork();

		if (pid < 0) {
			std::cerr << "Unable to start! Fork failed!" << std::endl;
			log.error("Unable to start! Fork failed!");
			exit(1);
		} else if (pid > 0) {// Parent (pid > 0)
			log.debug("Saving PID to file...");
			// Write PID to file
			std::ofstream f(PID_PATH);
			if (f.is_open()) {
				f << pid;
				f.close();
			} else {
				log.error("Failed to save PID!");
			}
			exit(0);
		} else {// Child (pid == 0), daemon process
			// To keep main loop running
			running = true;
			// For iptables rule removal check
			bool removeRule = false;
			std::size_t posip = config.iptablesRule.find("%i");
			std::string ruleStart = "";
			std::string ruleEnd = "";
			if (posip != std::string::npos) {
				ruleStart = config.iptablesRule.substr(0, posip);
				ruleEnd = config.iptablesRule.substr(posip + 2);
			}
			std::map<unsigned int, std::string> rules;
			std::map<unsigned int, std::string>::iterator rit;
			std::size_t checkStart = 0, checkEnd = 0;
			std::smatch regexSearchResults;
			std::regex ipSearchPattern("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
			std::string regexSearchResult;

			// Vars for expired rule removal checkIptables
			std::map<std::string, hb::SuspiciosAddressType>::iterator sait;

			// Compare data with iptables rules and add/remove rules if needed
			if (!data.checkIptables()) {
				log.error("Failed to compare data with iptables...");
			}

			// Register signal handler
			csignal::signal(SIGTERM, signalHandler);// Stop daemon
			csignal::signal(SIGUSR1, signalHandler);// Reload datafile

			// Close standard file descriptors
			cunistd::close(STDIN_FILENO);
			cunistd::close(STDOUT_FILENO);
			cunistd::close(STDERR_FILENO);

			// Init object to work with log files (check for suspicious activity)
			hb::LogParser logParser = hb::LogParser(&log, &config, &data);

			// File modification times (for main loop to check if there have been changes to files and relaod is needed)
			/*struct cstat::stat statbuf;
			time_t dataFileMTime;
			if (cstat::stat(config.dataFilePath.c_str(), &statbuf) == 0) {
				dataFileMTime = statbuf.st_mtime;
			}*/
			time_t lastFileMCheck, currentTime, lastLogCheck;
			time(&lastFileMCheck);
			lastLogCheck = lastFileMCheck - config.logCheckInterval;

			// For debug purposes write to log file how long each iteration took
			// clock_t iterStart, iterEnd;

			if (config.logLevel == "DEBUG") {
				initEnd = clock();
				log.debug("Daemon initialization exec time: " + std::to_string((double)(initEnd - initStart)/CLOCKS_PER_SEC) + " sec");
			}

			// Main loop
			while (running) {
				// Time at start of iteration
				// if (config.logLevel == "DEBUG") iterStart = clock();

				// Get current time
				time(&currentTime);

				// Each 60 sec check if datafile is updated and reload is needed
				/*if (currentTime - lastFileMCheck >= 60) {
					// Get datafile stats
					if (cstat::stat(config.dataFilePath.c_str(), &statbuf) == 0) {
						if (dataFileMTime != statbuf.st_mtime) {
							log.info("Datafile change detected, reloading data for daemon...");
							reloadDataFile = true;
						}
					}
					lastFileMCheck = currentTime;
				}*/

				// Reload configuration
				if (reloadConfig) {
					log.info("Daemon configuration reload...");
					if (!config.load()) {
						log.error("Failed to reload configuration for daemon!");
					}

					// Reset so that we do not reload on each iteration
					reloadConfig = false;

					// Recheck iptables rule since it can be changed in config
					posip = config.iptablesRule.find("%i");
					if (posip != std::string::npos) {

						// If rule has changed
						if (ruleStart != config.iptablesRule.substr(0, posip)
							|| ruleEnd != config.iptablesRule.substr(posip + 2)) {
							log.warning("iptables rule changed in configuration, updating iptables...");
							// Get all current rules
							rules = iptables.listRules("INPUT");
							// Loop all rules
							for(rit=rules.begin(); rit!=rules.end(); ++rit){
								checkStart = rit->second.find(ruleStart);
								checkEnd = rit->second.find(ruleEnd);
								checkEnd = rit->second.find(ruleEnd);
								if (checkStart != std::string::npos && checkEnd != std::string::npos) {
									// Find address in rule
									if (std::regex_search(rit->second, regexSearchResults, ipSearchPattern)) {
										if (regexSearchResults.size() == 1) {
											regexSearchResult = regexSearchResults[0].str();
											// Remove rule based on old config
											try {
												if (iptables.remove("INPUT", ruleStart + regexSearchResult + ruleEnd) == false) {
													log.error("Trying to update rule for address " + regexSearchResult + " based on updated configuraiton, but failed to remove current rule!");
												} else {
													sait->second.iptableRule = false;
												}
											} catch (std::runtime_error& e) {
												std::string message = e.what();
												log.error(message);
												log.error("Trying to update rule for address " + regexSearchResult + " based on updated configuraiton, but failed to remove current rule!");
											}

											// Add rule based on new config
											try {
												if (iptables.append("INPUT", config.iptablesRule.substr(0, posip) + regexSearchResult + config.iptablesRule.substr(posip + 2)) == false) {
													log.error("Trying to update rule for address " + regexSearchResult + " based on updated configuraiton, but failed to add rule based on new configuration!");
												} else {
													sait->second.iptableRule = true;
												}
											} catch (std::runtime_error& e) {
												std::string message = e.what();
												log.error(message);
												log.error("Trying to update rule for address " + regexSearchResult + " based on updated configuraiton, but failed to add rule based on new configuration!");
											}
										}
									}
								}
							}
						}

						// Update rule for daemon expired rule check
						ruleStart = config.iptablesRule.substr(0, posip);
						ruleEnd = config.iptablesRule.substr(posip + 2);
					}
				}

				// Reload datafile
				if (reloadDataFile) {
					log.info("Daemon datafile reload...");
					if (!data.loadData()) {
						log.error("Failed to reload data for daemon!");
					} else {
						// dataFileMTime = statbuf.st_mtime;
					}
					reloadDataFile = false;
				}

				if ((unsigned int)(currentTime - lastLogCheck) >= config.logCheckInterval) {
					// log.debug("currentTime: " + std::to_string(currentTime) + " lastLogCheck: " + std::to_string(lastLogCheck) + " diff: " + std::to_string((unsigned int)(currentTime - lastLogCheck)) + " logCheckInterval: " + std::to_string(config.logCheckInterval));

					// Check log files for suspicious activity and update iptables if needed
					logParser.checkFiles();

					// Check iptables rules if any are expired and should be removed
					for (sait = data.suspiciousAddresses.begin(); sait!=data.suspiciousAddresses.end(); ++sait) {
						// If address has rule
						if (sait->second.iptableRule) {
							// Reset rule removal flag
							removeRule = false;
							// Blacklisted addresses must have rule
							if (sait->second.blacklisted == true) {
								continue;
							}
							if (config.keepBlockedScoreMultiplier > 0) {
								// Score multiplier configured, recheck if score is no longer enough to keep this rule
								if ((unsigned long long int)currentTime > sait->second.lastActivity + sait->second.activityScore) {
									removeRule = true;
								}
							} else {
								// Without multiplier rules are kept until score is reset to 0
								if (sait->second.activityScore == 0) {
									removeRule = true;
								}
							}
							if (removeRule) {
								log.info("Address " + sait->first + " iptables rule expired, removing...");
								try {
									if (iptables.remove("INPUT", ruleStart + sait->first + ruleEnd) == false) {
										log.error("Address " + sait->first + " no longer needs iptables rule, but failed to remove rule from chain!");
									} else {
										sait->second.iptableRule = false;
									}
								} catch (std::runtime_error& e) {
									std::string message = e.what();
									log.error(message);
									log.error("Address " + sait->first + " no longer needs iptables rule, but failed to remove rule from chain!");
								}
							}
						}
					}

					// Update time of last log file check
					lastLogCheck = currentTime;
				}

				// Write exec time to log file
				/*if (config.logLevel == "DEBUG") {
					iterEnd = clock();
					log.debug("Daemon main loop iteration exec time: " + std::to_string((double)(iterEnd - iterStart)/CLOCKS_PER_SEC) + " sec");
				}*/

				// Sleep 1/5 of second
				cunistd::usleep(200000);
			}
			log.info("Daemon stop");
		}

		exit(0);
	} else {
		printUsage();
		exit(0);
	}
}
