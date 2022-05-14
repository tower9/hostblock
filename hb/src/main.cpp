/*
 * Hostblock
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
// Queue
#include <queue>
// Threads
#include <thread>
// Mutex
#include <mutex>
// Standard string library
#include <string>
// Date and time manipulation
#include <chrono>
// For libcurl in abuseipdb.h
// Note, suspecting that unistd.h includes some headers that are also needed for socket.h, but it gets under cunistd namespace and cannot find type socklen_t...?
#include <sys/socket.h>
// Miscellaneous UNIX symbolic constants, types and functions (fork, usleep, optarg)
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
// AbuseIPDB
#include "abuseipdb.h"

// Full path to PID file
const char* PID_PATH = "/var/run/hostblock.pid";

// Variables for loop and thread exception handling
bool running = false;
bool reportingThreadRunning = false;
std::mutex reportingThreadRunningMutex;

// Variable for daemon to reload data file
bool reloadDataFile = false;

// Variable for daemon to reload configuration
bool reloadConfig = false;

// Pending reports to be sent to 3rd party (abuse/suspicious activity reporting)
std::queue<hb::ReportToAbuseIPDB> abuseipdbReportingQueue;
std::mutex abuseipdbReportingQueueMutex;


/*
 * Output short help
 */
void printUsage()
{
	std::cout << "Hostblock v." << hb::kHostblockVersion << std::endl;
	std::cout << "https://github.com/tower9/hostblock" << std::endl;
	std::cout << std::endl;
	std::cout << "hostblock [-h | --help] [-s | --statistics] [-l | --list [-a | --all] [-c | --count] [-t | --time]] [-b<ip_address> | --blacklist=<ip_address>] [-w<ip_address> | --whitelist=<ip_address>] [-r<ip_address> | --remove=<ip_address>] [-d | --daemon]" << std::endl << std::endl;
	std::cout << " -h             | --help                   - this information" << std::endl;
	std::cout << " -p             | --print-config           - output configuration" << std::endl;
	std::cout << " -s             | --statistics             - statistics" << std::endl;
	std::cout << " -l             | --list                   - list of blocked suspicious IP addresses (excluding AbuseIPDB blacklist)" << std::endl;
	std::cout << " -a             | --all                    - list all IP addresses, not only blocked (excluding AbuseIPDB blacklist)" << std::endl;
	std::cout << " -lc            | --list --count           - list of blocked suspicious IP addresses with suspicious activity count, score and refused count (excluding AbuseIPDB blacklist)" << std::endl;
	std::cout << " -lt            | --list --time            - list of blocked suspicious IP addresses with last suspicious activity time (excluding AbuseIPDB blacklist)" << std::endl;
	std::cout << " -lct           | --list --count --time    - list of blocked suspicious IP addresses with suspicious activity count, score, refused count and last suspicious activity time (excluding AbuseIPDB blacklist)" << std::endl;
	std::cout << " -b<IP address> | --blacklist=<IP address> - toggle whether address is in blacklist" << std::endl;
	std::cout << " -w<IP address> | --whitelist=<IP address> - toggle whether address is in whitelist" << std::endl;
	std::cout << " -r<IP address> | --remove=<IP address>    - remove IP address from data file (excluding AbuseIPDB blacklist)" << std::endl;
	std::cout << " -d             | --daemon                 - run as daemon" << std::endl;
	std::cout << "                | --sync-blacklist         - sync AbuseIPDB blacklist" << std::endl;
}

/*
 * Signal handler
 */
void signalHandler(int signal)
{
	if (signal == SIGTERM) {
		// Stop daemon
		running = false;
		reportingThreadRunningMutex.lock();
		reportingThreadRunning = false;
		reportingThreadRunningMutex.unlock();
	} else if (signal == SIGUSR1) {
		// SIGUSR1 to tell daemon to reload data, config and restart threads if needed
		reloadDataFile = true;
		reloadConfig = true;
	}
}

/*
 * Thread for suspicious address reporting
 * Note, using config here only for reading, so mutex is used here and in main() for config changing
 * Note, syslog is marked as env&locale unsafe, but if env&locale do not change for this context then it should be ok...?
 */
void reporterThread(hb::Logger* log, hb::Config* config)
{
	log->info("Starting thread for activity reporting to AbuseIPDB...");
	hb::ReportToAbuseIPDB itemToReport;
	hb::AbuseIPDB apiClient = hb::AbuseIPDB(log, config);
	bool isEmpty = false;
	while (true) {
		// Check whether should exit this loop
		reportingThreadRunningMutex.lock();
		if (!reportingThreadRunning) {
			reportingThreadRunningMutex.unlock();
			break;
		}
		reportingThreadRunningMutex.unlock();

		// Take out one item from queue
		abuseipdbReportingQueueMutex.lock();
		isEmpty = abuseipdbReportingQueue.empty();
		abuseipdbReportingQueueMutex.unlock();
		if (!isEmpty) {
			abuseipdbReportingQueueMutex.lock();
			itemToReport = abuseipdbReportingQueue.front();
			abuseipdbReportingQueue.pop();
			abuseipdbReportingQueueMutex.unlock();

			// Send report (API client can decide to not actually report if either per minute or daily limit is reached)
			if (apiClient.reportAddress(itemToReport.ip, itemToReport.comment, itemToReport.categories)) {
				log->info("Address " + itemToReport.ip + " reported to AbuseIPDB!");
				// log->debug("Comment: " + itemToReport.comment);
			}
		}

		// Sleep a little
		cunistd::usleep(2000);
	}
	log->info("Thread for Activity reporting to AbuseIPDB stopped");
}

/*
 * Syncrhonize AbuseIPDB blacklist
 */
void blacklistSync(hb::Logger* log, hb::Config* config, hb::Data* data, hb::Iptables* iptables)
{
	clock_t cpuStart = clock(), cpuEnd = cpuStart;
	auto wallStart = std::chrono::steady_clock::now(), wallEnd = wallStart;
	log->debug("Starting AbuseIPDB blacklist sync...");

	hb::AbuseIPDB apiClient = hb::AbuseIPDB(log, config);

	std::map<std::string, hb::AbuseIPDBBlacklistedAddressType> newBlacklist;
	unsigned long long int blacklistGenTime;

	if (apiClient.getBlacklist(config->abuseipdbBlockScore, &blacklistGenTime, &newBlacklist) == false) {
		throw std::runtime_error("Failed to get blacklist from AbuseIPDB API!");
	} else {
		std::time_t currentRawTime;
		std::time(&currentRawTime);
		unsigned long long int currentTime = (unsigned long long int)currentRawTime;
		data->abuseIPDBSyncTime = currentTime;
		std::map<std::string, hb::AbuseIPDBBlacklistedAddressType>::iterator itb;

		log->info("AbuseIPDB blacklist generation time: " + hb::Util::formatDateTime((const time_t)blacklistGenTime, config->dateTimeFormat.c_str()) + " AbuseIPDB blacklist size: " + std::to_string(newBlacklist.size()));

		if (data->abuseIPDBBlacklistGenTime > blacklistGenTime) {
			log->warning("Received older AbuseIPDB blacklist generation time than with previous sync process!");
		} else if (data->abuseIPDBBlacklistGenTime == blacklistGenTime) {
			log->warning("Received the same AbuseIPDB blacklist generation time as in previous sync process! Too frequent syncrhonization process?");
		}
		data->abuseIPDBBlacklistGenTime = blacklistGenTime;

		// Loop old blacklist
		std::vector<std::string> forAppend;
		std::vector<std::string> forUpdate;
		std::vector<std::string> forRemoval;
		for (itb = data->abuseIPDBBlacklist.begin(); itb!=data->abuseIPDBBlacklist.end(); ++itb) {
			if (newBlacklist.count(itb->first) > 0) {
				// Address in old blacklist is also found in new blacklist
				forUpdate.push_back(itb->first);
				itb->second.totalReports = newBlacklist[itb->first].totalReports;
				itb->second.abuseConfidenceScore = newBlacklist[itb->first].abuseConfidenceScore;
			} else {
				// Address in old blacklist is not found in new blacklist
				forRemoval.push_back(itb->first);
				itb = data->abuseIPDBBlacklist.erase(itb);// Returns next item after removed one
				if (itb != data->abuseIPDBBlacklist.begin()) {
					--itb;// Don't skip the next item
				}
			}
		}

		if (forUpdate.size() > 0) {
			data->updateAbuseIPDBAddresses(&forUpdate);
		}
		if (forRemoval.size() > 0) {
			data->removeAbuseIPDBAddresses(&forRemoval);
			// Also remove iptables rules
			// iptables->remove("INPUT", &forRemoval);// Need rule start & end parsed from config
			for (auto itr = forRemoval.begin(); itr != forRemoval.end(); ++itr) {
				data->updateIptables(*itr);
			}
		}

		// Loop new blacklist
		hb::AbuseIPDBBlacklistedAddressType record;
		for (itb = newBlacklist.begin(); itb != newBlacklist.end(); ++itb) {
			if (data->abuseIPDBBlacklist.count(itb->first) == 0) {
				forAppend.push_back(itb->first);
				record.totalReports = itb->second.totalReports;
				record.abuseConfidenceScore = itb->second.abuseConfidenceScore;
				record.iptableRule = false;
				record.version = hb::Util::ipVersion(itb->first);
				data->abuseIPDBBlacklist.insert(std::pair<std::string,hb::AbuseIPDBBlacklistedAddressType>(itb->first, record));
			}
		}

		if (forAppend.size() > 0) {
			data->addAbuseIPDBAddresses(&forAppend);
		}

		log->info("AbuseIPDB blacklist changes: " + std::to_string(forAppend.size()) + " new, " + std::to_string(forUpdate.size()) + " updated, " + std::to_string(forRemoval.size()) + " removed");

		// Update sync timestamps in datafile
		if (data->updateAbuseIPDBSyncData(data->abuseIPDBSyncTime, data->abuseIPDBBlacklistGenTime) == false) {
			throw std::runtime_error("Failed to update AbuseIPDB blacklist sync data in datafile!");
		}

	}

	cpuEnd = clock();
	wallEnd = std::chrono::steady_clock::now();
	log->info("AbuseIPDB blacklist sync in " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
}

/*
 * Main
 */
int main(int argc, char *argv[])
{
	clock_t cpuStart = clock(), cpuEnd = cpuStart;
	auto wallStart = std::chrono::steady_clock::now(), wallEnd = wallStart;

	// Must have at least one argument
	if (argc < 2) {
		printUsage();
		exit(0);
	}

	// Option flags
	int c;
	bool printConfigFlag = false;
	bool statisticsFlag = false;
	bool listFlag = false;
	bool allFlag = false;
	bool countFlag = false;
	bool timeFlag = false;
	bool blacklistFlag = false;
	bool whitelistFlag = false;
	bool removeFlag = false;
	bool syncBlacklistFlag = false;
	std::string ipAddress = "";
	bool daemonFlag = false;

	// Options
	static struct cgetopt::option long_options[] =
	{
		{"help",           no_argument,       0, 'h'},
		{"print-config",   no_argument,       0, 'p'},
		{"statistics",     no_argument,       0, 's'},
		{"list",           no_argument,       0, 'l'},
		{"all",            no_argument,       0, 'a'},
		{"count",          no_argument,       0, 'c'},
		{"time",           no_argument,       0, 't'},
		{"blacklist",      required_argument, 0, 'b'},
		{"whitelist",      required_argument, 0, 'w'},
		{"remove",         required_argument, 0, 'r'},
		{"daemon",         no_argument,       0, 'd'},
		{"sync-blacklist", no_argument,       0, 0},
	};

	// Option index
	int option_index = 0;

	// Check options
	while ((c = cgetopt::getopt_long(argc, argv, "hpslactb:w:r:d", long_options, &option_index)) != -1)
		switch (c) {
			case 0:
				if (strncmp("sync-blacklist", long_options[option_index].name, strlen(long_options[option_index].name)) == 0) {
					syncBlacklistFlag = true;
				} else {
					printUsage();
					exit(0);
				}
				break;
			case 'h':
				printUsage();
				exit(0);
				break;
			case 'p':
				printConfigFlag = true;
				break;
			case 's':
				statisticsFlag = true;
				break;
			case 'l':
				listFlag = true;
				break;
			case 'a':
				allFlag = true;
				break;
			case 'c':
				countFlag = true;
				break;
			case 't':
				timeFlag = true;
				break;
			case 'b':
				blacklistFlag = true;
				ipAddress = cunistd::optarg;
				break;
			case 'w':
				whitelistFlag = true;
				ipAddress = cunistd::optarg;
				break;
			case 'r':
				removeFlag = true;
				ipAddress = cunistd::optarg;
				break;
			case 'd':
				daemonFlag = true;
				break;
			default:
				printUsage();
				exit(0);
		}

	// Syslog writter
	hb::Logger log = hb::Logger(LOG_USER);

	// To work with iptables
	hb::Iptables iptables = hb::Iptables();
	/*hb::Iptables* iptables;
	try {
		// hb::Iptables iptables = hb::Iptables();
		iptables = hb::Iptables();
	} catch (std::runtime_error& e) {
		std::string message = e.what();
		log.error(message);
		std::cerr << message << std::endl;
		exit(1);
	}*/

	// Init config, default path to config file is /etc/hostblock.conf
	hb::Config config = hb::Config(&log, "/etc/hostblock.conf");

	// If env variable $HOSTBLOCK_CONFIG is set, then use value from it as path to config
	if (const char* env_cp = std::getenv("HOSTBLOCK_CONFIG")) {
		config.configPath = std::string(env_cp);
	}

	// Load config
	try {
		if (!config.load()) {
			std::cerr << "Failed to load configuration from file!" << std::endl;
			exit(1);
		}
	} catch (std::runtime_error &e) {
		std::string message = e.what();
		std::cerr << message << std::endl;
		exit(1);
	}

	// To work with datafile
	hb::Data data = hb::Data(&log, &config, &iptables);

	// Load datafile
	if (!data.loadData()) {
		std::cerr << "Failed to load data!" << std::endl;
		exit(1);
	}

	if (printConfigFlag) {// Output configuration
		config.print();
		if (config.logLevel == "DEBUG") {
			cpuEnd = clock();
			wallEnd = std::chrono::steady_clock::now();
			log.debug("Configuration outputed in " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
		}
		exit(0);
	} else if (statisticsFlag) {// Output statistics
		data.printStats();
		if (config.logLevel == "DEBUG") {
			cpuEnd = clock();
			wallEnd = std::chrono::steady_clock::now();
			log.debug("Statistics outputed in " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
		}
		exit(0);
	} else if (listFlag) {// 	Output list of addresses/blocked suspicious addresses
		data.printBlocked(countFlag, timeFlag, allFlag);
		if (config.logLevel == "DEBUG") {
			cpuEnd = clock();
			wallEnd = std::chrono::steady_clock::now();
			log.debug("List of addresses/blocked addresses outputed in " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
		}
		exit(0);
	} else if (blacklistFlag) {// Toggle whether address is in blacklist
		// Save address if there is no previous activity from this address
		if (data.suspiciousAddresses.count(ipAddress) == 0) {
			std::time_t currentTime;
			std::time(&currentTime);
			hb::SuspiciosAddressType dataRecord;
			dataRecord.lastActivity = (unsigned long long int)currentTime;
			data.suspiciousAddresses.insert(std::pair<std::string,hb::SuspiciosAddressType>(ipAddress, dataRecord));
			data.addAddress(ipAddress);
		}

		if (data.suspiciousAddresses[ipAddress].whitelisted) {
			// If address is in whitelist, ask user to confirm
			std::cout << "Address is already whitelisted, would you like to remove it from whitelist and add to blacklist instead? [y/n]";
			char choice = 'n';
			std::cin >> choice;
			if (choice == 'y') {
				data.suspiciousAddresses[ipAddress].whitelisted = false;
				data.suspiciousAddresses[ipAddress].blacklisted = true;
				data.updateAddress(ipAddress);
			}
		} else {
			// Address not in whitelist, just change blacklisted flag
			if (data.suspiciousAddresses[ipAddress].blacklisted) {
				data.suspiciousAddresses[ipAddress].blacklisted = false;
			} else {
				data.suspiciousAddresses[ipAddress].blacklisted = true;
			}
			data.updateAddress(ipAddress);
		}

		// If daemon is running, signal to reload datafile
		struct cstat::stat buffer;
		if (cstat::stat(PID_PATH, &buffer) == 0) {
			// Get PID from file
			std::ifstream f(PID_PATH);
			if (f.is_open()){
				std::string line;
				std::getline(f, line);
				pid_t pid = (pid_t)strtoul(line.c_str(), NULL, 10);
				// If process with this PID exists
				if (csignal::kill(pid, 0) == 0) {
					// Send SIGUSR1
					if (csignal::kill(pid, SIGUSR1) != 0) {
						std::cout << "Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed." << std::endl;
						log.warning("Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed.");
					}
				}
			}
		}

		if (config.logLevel == "DEBUG") {
			cpuEnd = clock();
			wallEnd = std::chrono::steady_clock::now();
			log.debug("Address blacklist change " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
		}
		exit(0);
	} else if (whitelistFlag) {// Toggle whether address is in whitelist
		// Save address if there is no previous activity from this address
		if (data.suspiciousAddresses.count(ipAddress) == 0) {
			std::time_t currentTime;
			std::time(&currentTime);
			hb::SuspiciosAddressType dataRecord;
			dataRecord.lastActivity = (unsigned long long int)currentTime;
			data.suspiciousAddresses.insert(std::pair<std::string,hb::SuspiciosAddressType>(ipAddress, dataRecord));
			data.addAddress(ipAddress);
		}

		if (data.suspiciousAddresses[ipAddress].blacklisted) {
			// If address is in whitelist, ask user to confirm
			std::cout << "Address is already blacklisted, would you like to remove it from blacklist and add to whitelist instead? [y/n]";
			char choice = 'n';
			std::cin >> choice;
			if (choice == 'y') {
				data.suspiciousAddresses[ipAddress].blacklisted = false;
				data.suspiciousAddresses[ipAddress].whitelisted = true;
				data.updateAddress(ipAddress);
			}
		} else {
			// Address not in whitelist, just change blacklisted flag
			if (data.suspiciousAddresses[ipAddress].whitelisted) {
				data.suspiciousAddresses[ipAddress].whitelisted = false;
			} else {
				data.suspiciousAddresses[ipAddress].whitelisted = true;
			}
			data.updateAddress(ipAddress);
		}

		// If daemon is running, signal to reload datafile
		struct cstat::stat buffer;
		if (cstat::stat(PID_PATH, &buffer) == 0) {
			// Get PID from file
			std::ifstream f(PID_PATH);
			if (f.is_open()){
				std::string line;
				std::getline(f, line);
				pid_t pid = (pid_t)strtoul(line.c_str(), NULL, 10);
				// If process with this PID exists
				if (csignal::kill(pid, 0) == 0) {
					// Send SIGUSR1
					if (csignal::kill(pid, SIGUSR1) != 0) {
						std::cout << "Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed." << std::endl;
						log.warning("Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed.");
					}
				}
			}
		}

		if (config.logLevel == "DEBUG") {
			cpuEnd = clock();
			wallEnd = std::chrono::steady_clock::now();
			log.debug("Address whitelist change " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
		}
		exit(0);
	} else if (removeFlag) {// Remove address from datafile
		if (data.suspiciousAddresses.count(ipAddress) > 0) {
			if (!data.removeAddress(ipAddress)) {
				std::cerr << "Failed to remove address!" << std::endl;
				exit(1);
			} else {
				// Check if there is iptables rule for this address
				std::vector<std::string> rules;
				iptables.listRules("INPUT", rules, 4);
				iptables.listRules("INPUT", rules, 6);
				try {

					// Regex to search for IP address
					std::regex ipSearchPattern(hb::kIpSearchPattern);

					// Loop through all rules
					std::vector<std::string>::iterator rit;
					std::size_t checkStart = 0, checkEnd = 0;
					std::smatch regexSearchResults;
					std::string regexSearchResult;
					std::size_t posip = config.iptablesRule.find("%i");
					std::string ruleStart = "";
					std::string ruleEnd = "";
					if (posip != std::string::npos) {
						ruleStart = config.iptablesRule.substr(0, posip);
						ruleEnd = config.iptablesRule.substr(posip + 2);
					}
					for (rit = rules.begin(); rit != rules.end(); ++rit) {
						checkStart = (*rit).find(ruleStart);
						checkEnd = (*rit).find(ruleEnd);
						if (checkStart != std::string::npos && checkEnd != std::string::npos) {
							if (std::regex_search((*rit), regexSearchResults, ipSearchPattern)) {
								if (regexSearchResults.size() == 1) {
									regexSearchResult = regexSearchResults[0].str();
									if (regexSearchResult == ipAddress) {
										// iptables rule found, remove from iptables
										if (iptables.remove("INPUT", ruleStart + ipAddress + ruleEnd) == false) {
											std::cerr << "Address " << ipAddress << " no longer needs iptables rule, but failed to remove rule from chain!" << std::endl;
											log.error("Address " + ipAddress + " no longer needs iptables rule, but failed to remove rule from chain!");
											exit(1);
										}
									}
								}
							}
						}
					}

				} catch (std::regex_error& e) {
					std::string message = e.what();
					log.error(message + ": " + std::to_string(e.code()));
					log.error(hb::Util::regexErrorCode2Text(e.code()));
					std::cerr << "iptables check failed!" << std::endl;
					exit(1);
				}
			}
		} else {
			std::cout << "Unable to remove " << ipAddress << ", address not found in datafile!" << std::endl;
			log.error("Unable to remove " + ipAddress + ", address not found in datafile!");
		}

		// If daemon is running, signal to reload datafile
		struct cstat::stat buffer;
		if (cstat::stat(PID_PATH, &buffer) == 0) {
			// Get PID from file
			std::ifstream f(PID_PATH);
			if (f.is_open()){
				std::string line;
				std::getline(f, line);
				pid_t pid = (pid_t)strtoul(line.c_str(), NULL, 10);
				// If process with this PID exists
				if (csignal::kill(pid, 0) == 0) {
					// Send SIGUSR1
					if (csignal::kill(pid, SIGUSR1) != 0) {
						std::cout << "Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed." << std::endl;
						log.warning("Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed.");
					}
				}
			}
		}

		if (config.logLevel == "DEBUG") {
			cpuEnd = clock();
			wallEnd = std::chrono::steady_clock::now();
			log.debug("Address removed in " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
		}
		exit(0);
	} else if (syncBlacklistFlag) {// Sync AbuseIPDB blacklist
		std::cout << "Starting AbuseIPDB blacklist sync, please wait..." << std::endl;

		try {
			blacklistSync(&log, &config, &data, &iptables);
		} catch (std::runtime_error& e) {
			std::string message = e.what();
			log.error(message);
			std::cerr << message << std::endl;
			std::cerr << "AbuseIPDB blacklist sync failed!" << std::endl;
			exit(1);
		}

		// If daemon is running, signal to reload datafile
		struct cstat::stat buffer;
		if (cstat::stat(PID_PATH, &buffer) == 0) {
			// Get PID from file
			std::ifstream f(PID_PATH);
			if (f.is_open()){
				std::string line;
				std::getline(f, line);
				pid_t pid = (pid_t)strtoul(line.c_str(), NULL, 10);
				// If process with this PID exists
				if (csignal::kill(pid, 0) == 0) {
					// Send SIGUSR1
					if (csignal::kill(pid, SIGUSR1) != 0) {
						std::cout << "Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed." << std::endl;
						log.warning("Daemon process detected, but failed to signal datafile reload. Restart daemon manually if needed.");
					}
				}
			}
		}

		std::cout << "Finished" << std::endl;
		exit(0);
	} else if (daemonFlag) {// Run as daemon

		// Check if file with PID exists
		struct cstat::stat buffer;
		if (cstat::stat(PID_PATH, &buffer) == 0) {
			// Get PID from file
			std::ifstream f(PID_PATH);
			if (f.is_open()){
				std::string line;
				std::getline(f, line);
				pid_t pid = (pid_t)strtoul(line.c_str(), NULL, 10);
				if (csignal::kill(pid, 0) == 0) {
					// Process with this pid exists
					std::cerr << "Unable to start! Another instance of hostblock is already running!" << std::endl;
					log.error("Unable to start! Another instance of hostblock is already running!");
					exit(1);
				} else {
					// Process does not exist, remove pid file
					std::remove(PID_PATH);
				}
			} else {
				std::cerr << "Unable to start! Failed to check if hostblock is already running!" << std::endl;
				log.error("Unable to start! Failed to check if hostblock is already running!");
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
			log.info("Starting hostblock daemon...");

			// Parse regex patterns
			if (!config.processPatterns()) {
				std::cerr << "Failed to parse configured patterns!" << std::endl;
				exit(1);
			}

			// To keep main loop running
			running = true;

			// iptables commands for execution during daemon startup
			if (!config.iptablesStartupCheck.empty()) {
				// IPv4
				if (iptables.command(config.iptablesStartupCheck + ">/dev/null 2>/dev/null") != 0) {
					log.info("Executing iptables startup commands...");
					int response = 0;
					for (std::vector<std::string>::iterator it = config.iptablesStartupAdd.begin(); it != config.iptablesStartupAdd.end(); ++it) {
						log.debug("iptables " + *it);
						response = iptables.command(*it);
						if (response != 0) {
							log.error("Failed to execute iptables command '" + *it + "', return code: " + std::to_string(response));
						}
					}
				}
				// IPv6
				if (iptables.command(config.iptablesStartupCheck + ">/dev/null 2>/dev/null", 6) != 0) {
					log.info("Executing ip6tables startup commands...");
					int response = 0;
					for (std::vector<std::string>::iterator it = config.iptablesStartupAdd.begin(); it != config.iptablesStartupAdd.end(); ++it) {
						log.debug("ip6tables " + *it);
						response = iptables.command(*it, 6);
						if (response != 0) {
							log.error("Failed to execute ip6tables command '" + *it + "', return code: " + std::to_string(response));
						}
					}
				}
			}

			// For iptables rule check
			std::size_t posip = config.iptablesRule.find("%i");
			std::string ruleStart = "";
			std::string ruleEnd = "";
			if (posip != std::string::npos) {
				ruleStart = config.iptablesRule.substr(0, posip);
				ruleEnd = config.iptablesRule.substr(posip + 2);
			}
			std::vector<std::string> rules;
			std::vector<std::string>::iterator rit;
			std::size_t checkStart = 0, checkEnd = 0;
			std::smatch regexSearchResults;
			std::regex ipSearchPattern(hb::kIpSearchPattern);
			std::string regexSearchResult;
			std::map<std::string, hb::SuspiciosAddressType>::iterator sait;

			// Compare data with iptables rules and add/remove rules if needed
			if (!data.checkIptables()) {
				log.error("Failed to compare data with iptables...");
			}

			// Register signal handler
			csignal::signal(SIGTERM, signalHandler);// Stop daemon
			csignal::signal(SIGUSR1, signalHandler);// Reload datafile

			// Fire up thread for matched pattern reporting
			reportingThreadRunning = true;// No need for mutex, no threads are running yet
			std::thread abuseipdbReporterThread(&reporterThread, &log, &config);

			// Close standard file descriptors
			cunistd::close(STDIN_FILENO);
			cunistd::close(STDOUT_FILENO);
			cunistd::close(STDERR_FILENO);

			// Init object to work with log files (check for suspicious activity)
			hb::LogParser logParser = hb::LogParser(&log, &config, &data, &abuseipdbReportingQueue, &abuseipdbReportingQueueMutex);

			time_t lastFileMCheck, currentTime, lastLogCheck;
			time(&lastFileMCheck);
			lastLogCheck = lastFileMCheck - config.logCheckInterval;

			if (config.logLevel == "DEBUG") {
				cpuEnd = clock();
				wallEnd = std::chrono::steady_clock::now();
				log.debug("Daemon initialization exec time: " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");
			}

			// Main loop
			while (running) {

				// Get current time
				time(&currentTime);

				// Reload configuration
				if (reloadConfig) {
					log.info("Daemon configuration reload...");
					ruleStart = config.iptablesRule.substr(0, posip);
					ruleEnd = config.iptablesRule.substr(posip + 2);
					if (!config.load()) {
						log.error("Failed to reload configuration for daemon!");
					}

					// Parse regex patterns
					if (!config.processPatterns()) {
						log.error("Failed to parse configured patterns for daemon!");
					}

					// Reset config relad flag (so that it is not reladed again on next iteration)
					reloadConfig = false;

					// Recheck iptables rule after config reload (it might be changed)
					posip = config.iptablesRule.find("%i");
					if (posip != std::string::npos) {

						// If rule has changed
						if (ruleStart != config.iptablesRule.substr(0, posip)
							|| ruleEnd != config.iptablesRule.substr(posip + 2)) {
							log.warning("iptables rule changed in configuration, updating iptables...");

							// Get all current rules for INPUT chain
							rules.clear();
							iptables.listRules("INPUT", rules, 4);
							iptables.listRules("INPUT", rules, 6);

							// Loop all rules
							for (rit = rules.begin(); rit != rules.end(); ++rit) {
								checkStart = (*rit).find(ruleStart);
								checkEnd = (*rit).find(ruleEnd);
								checkEnd = (*rit).find(ruleEnd);
								if (checkStart != std::string::npos && checkEnd != std::string::npos) {

									// Find address in rule
									if (std::regex_search((*rit), regexSearchResults, ipSearchPattern)) {
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
												bool res = false;
												if (config.iptablesAppend) {
													res = iptables.append("INPUT", config.iptablesRule.substr(0, posip) + regexSearchResult + config.iptablesRule.substr(posip + 2));
												} else {
													res = iptables.insert("INPUT", config.iptablesRule.substr(0, posip) + regexSearchResult + config.iptablesRule.substr(posip + 2));
												}
												if (res == false) {
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

					}
				}

				// Reload datafile
				if (reloadDataFile) {
					log.info("Daemon datafile reload...");
					if (!data.loadData()) {
						log.error("Failed to reload data for daemon!");
					}
					if (!data.checkIptables()) {
						log.error("Failed to compare data with iptables...");
					}
					reloadDataFile = false;
				}

				// Log file check
				if ((unsigned int)(currentTime - lastLogCheck) >= config.logCheckInterval) {

					// Check log files for suspicious activity and update iptables if needed
					// TODO make this function responsive to kill
					// TODO check file size also in this function since this proces can take more time than log rotate
					logParser.checkFiles();

					// Check iptables rules if any are expired and should be removed
					for (sait = data.suspiciousAddresses.begin(); sait != data.suspiciousAddresses.end(); ++sait) {
						if (sait->second.iptableRule) {
							data.updateIptables(sait->first);
						}
					}

					// Update time of last log file check
					lastLogCheck = currentTime;
				}

				// AbuseIPDB blacklist sync
				if (config.abuseipdbKey.size() > 0 && config.abuseipdbBlacklistInterval > 0 && (unsigned int)(currentTime - data.abuseIPDBSyncTime) >= config.abuseipdbBlacklistInterval) {
					try {
						blacklistSync(&log, &config, &data, &iptables);
						reloadDataFile = true;
					} catch (std::runtime_error& e) {
						log.error(e.what());
						data.abuseIPDBSyncTime += 300;// Wait for a while before retry
					}
				}

				// Sleep 1/5 of a second
				cunistd::usleep(200000);
			}
			abuseipdbReporterThread.join();
			log.info("Hostblock daemon stop");
		}

		exit(0);
	} else {
		printUsage();
		exit(0);
	}
}
