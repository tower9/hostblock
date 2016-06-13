// Standard input/output stream library (cin, cout, cerr, clog)
#include <iostream>
// Time (clock_t, clock())
#include <time.h>
// Standard map library
#include <map>
// Standard vector library
#include <vector>
// Syslog
namespace csyslog{
	#include <syslog.h>
}
// Logger
#include "../src/logger.h"
// Iptables
#include "../src/iptables.h"
// Config
#include "../src/config.h"
// Data
#include "../src/data.h"
// LogParser
#include "../src/logparser.h"

int main(int argc, char *argv[])
{
	clock_t start = clock();
	clock_t end;

	time_t currentTime;
	time(&currentTime);

	bool testSyslog = false;
	bool testIptables = false;
	bool testConfig = false;
	bool testData = false;
	bool removeTempData = false;
	bool testLogParsing = false;
	bool testConfiguredLogParsing = true;

	try{
		// Syslog
		std::cout << "Creating Logger object..." << std::endl;
		hb::Logger log = hb::Logger(LOG_USER);// LOG_USER is facility, priority is changed by setlevel
		if (testSyslog){
			log.setLevel(LOG_ERR);
			std::cout << "Writting to syslog with level LOG_ERR..." << std::endl;
			log.info("Syslog test - level: LOG_ERR msg type: info");
			log.warning("Syslog test - level: LOG_ERR msg type: warning");
			log.error("Syslog test - level: LOG_ERR msg type: error");
			log.debug("Syslog test - level: LOG_ERR msg type: debug");
			log.setLevel(LOG_WARNING);
			std::cout << "Writting to syslog with level LOG_WARNING..." << std::endl;
			log.info("Syslog test - level: LOG_WARNING msg type: info");
			log.warning("Syslog test - level: LOG_WARNING msg type: warning");
			log.error("Syslog test - level: LOG_WARNING msg type: error");
			log.debug("Syslog test - level: LOG_WARNING msg type: debug");
			log.setLevel(LOG_NOTICE);
			std::cout << "Writting to syslog with level LOG_NOTICE..." << std::endl;
			log.info("Syslog test - level: LOG_NOTICE msg type: info");
			log.warning("Syslog test - level: LOG_NOTICE msg type: warning");
			log.error("Syslog test - level: LOG_NOTICE msg type: error");
			log.debug("Syslog test - level: LOG_NOTICE msg type: debug");
			log.setLevel(LOG_INFO);
			std::cout << "Writting to syslog with level LOG_INFO..." << std::endl;
			log.info("Syslog test - level: LOG_INFO msg type: info");
			log.warning("Syslog test - level: LOG_INFO msg type: warning");
			log.error("Syslog test - level: LOG_INFO msg type: error");
			log.debug("Syslog test - level: LOG_INFO msg type: debug");
			log.setLevel(LOG_DEBUG);
			std::cout << "Writting to syslog with level LOG_DEBUG..." << std::endl;
			log.info("Syslog test - level: LOG_DEBUG msg type: info");
			log.warning("Syslog test - level: LOG_DEBUG msg type: warning");
			log.error("Syslog test - level: LOG_DEBUG msg type: error");
			log.debug("Syslog test - level: LOG_DEBUG msg type: debug");
		}
		log.setLevel(LOG_DEBUG);

		// iptables
		std::cout << "Creating Iptables object..." << std::endl;
		hb::Iptables iptbl = hb::Iptables();
		if (testIptables){
			std::map<unsigned int, std::string> rules;
			std::map<unsigned int, std::string>::iterator ruleIt;
			std::cout << "iptable rules (INPUT):" << std::endl;
			rules = iptbl.listRules("INPUT");
			for(ruleIt=rules.begin(); ruleIt!=rules.end(); ++ruleIt){
				std::cout << "Rule: " << ruleIt->second << std::endl;
			}
			std::cout << "Adding rule to drop all connections from 10.10.10.10..." << std::endl;
			if(iptbl.append("INPUT","-s 10.10.10.10 -j DROP") == false){
				std::cerr << "Failed to add rule for address 10.10.10.10" << std::endl;
			}
			std::cout << "iptable rules (INPUT):" << std::endl;
			rules = iptbl.listRules("INPUT");
			for(ruleIt=rules.begin(); ruleIt!=rules.end(); ++ruleIt){
				std::cout << "Rule: " << ruleIt->second << std::endl;
			}
			std::cout << "Removing rule for address 10.10.10.10..." << std::endl;
			if(iptbl.remove("INPUT","-s 10.10.10.10 -j DROP") == false){
				std::cerr << "Failed to remove rule for address 10.10.10.10" << std::endl;
			}
			std::cout << "iptable rules (INPUT):" << std::endl;
			rules = iptbl.listRules("INPUT");
			for(ruleIt=rules.begin(); ruleIt!=rules.end(); ++ruleIt){
				std::cout << "Rule: " << ruleIt->second << std::endl;
			}
		}

		// Config
		std::cout << "Creating Config object..." << std::endl;
		hb::Config cfg = hb::Config(&log, "config/hostblock.conf");
		std::cout << "Loading configuration file..." << std::endl;
		if (!cfg.load()){
			std::cerr << "Failed to load configuration!" << std::endl;
		}
		if (testConfig){
			std::cout << "Printing configuration to stdout..." << std::endl;
			cfg.print();
		}

		// Data
		std::cout << "Creating Data object..." << std::endl;
		std::vector<hb::LogGroup>::iterator itlg;
		std::vector<hb::LogFile>::iterator itlf;
		hb::Data data = hb::Data(&log, &cfg, &iptbl);
		cfg.dataFilePath = "hb/test/test_data";
		std::cout << "Loading data..." << std::endl;
		if (!data.loadData()) {
			std::cerr << "Failed to load data!" << std::endl;
		}
		if (testData || testLogParsing){
			// Create new data file
			std::cout << "Creating new data file..." << std::endl;
			cfg.dataFilePath = "test_data_tmp";
			if (!data.saveData()) {
				std::cerr << "Failed to save data to datafile!" << std::endl;
			}
			std::cout << "suspiciousAddresses.size = " << std::to_string(data.suspiciousAddresses.size()) << std::endl;
			// Append single record to datafile
			std::cout << "Adding 10.10.10.15 to data file..." << std::endl;
			hb::SuspiciosAddressType rec;
			rec.lastActivity = (unsigned long long int)currentTime;
			rec.activityScore = 99;
			rec.activityCount = 3;
			rec.refusedCount = 2;
			rec.whitelisted = false;
			rec.blacklisted = true;
			data.suspiciousAddresses.insert(std::pair<std::string,hb::SuspiciosAddressType>("10.10.10.15",rec));
			if (!data.addAddress("10.10.10.15")) {
				std::cerr << "Failed to add new record to datafile!" << std::endl;
			}
			// Update single record in datafile
			std::cout << "Updating 10.10.10.15 in data file..." << std::endl;
			data.suspiciousAddresses["10.10.10.15"].activityScore += 10;
			data.suspiciousAddresses["10.10.10.15"].activityCount++;
			data.suspiciousAddresses["10.10.10.15"].lastActivity = (unsigned long long int)currentTime;
			if (!data.updateAddress("10.10.10.15")) {
				std::cerr << "Failed to update record in datafile!" << std::endl;
			}
			std::cout << "Updating 10.10.10.14 in data file..." << std::endl;
			data.suspiciousAddresses["10.10.10.14"].lastActivity = (unsigned long long int)currentTime;
			if (!data.updateAddress("10.10.10.14")) {
				std::cerr << "Failed to update record in datafile!" << std::endl;
			}
			// Remove single record from datafile
			std::cout << "Removing 10.10.10.13 from data file..." << std::endl;
			if (!data.removeAddress("10.10.10.13")) {
				std::cerr << "Failed to remove record from datafile!" << std::endl;
			}
			// Add new log file to datafile
			std::cout << "Adding /var/log/messages to data file..." << std::endl;
			for (itlg = cfg.logGroups.begin(); itlg != cfg.logGroups.end(); ++itlg) {
				if (itlg->name == "OpenSSH") {
					hb::LogFile logFile;
					logFile.path = "/var/log/messages";
					logFile.bookmark = 800;
					logFile.size = 800;
					itlg->logFiles.push_back(logFile);
					break;
				}
			}
			if (!data.addFile("/var/log/messages")) {
				std::cerr << "Failed to add new record to datafile!" << std::endl;
			}
			// Update bookmark and size for log file in datafile
			std::cout << "Updating /var/log/messages in data file..." << std::endl;
			for (itlg = cfg.logGroups.begin(); itlg != cfg.logGroups.end(); ++itlg) {
				for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
					if (itlf->path == "/var/log/messages") {
						itlf->bookmark += 100;
						itlf->size += 100;
						break;
					}
				}
			}
			if (!data.updateFile("/var/log/messages")) {
				std::cerr << "Failed to update record in datafile!" << std::endl;
			}
			// Remove log file record from datafile
			std::cout << "Removing /var/log/auth.log from data file..." << std::endl;
			if (!data.removeFile("/var/log/auth.log")) {
				std::cerr << "Failed to remove record from datafile!" << std::endl;
			}
			// Remove log file record from datafile
			std::cout << "Removing /var/log/apache2/access.log from data file..." << std::endl;
			if (!data.removeFile("/var/log/apache2/access.log")) {
				std::cerr << "Failed to remove record from datafile!" << std::endl;
			}
			// Remove log file record from datafile
			std::cout << "Removing /var/log/messages from data file..." << std::endl;
			if (!data.removeFile("/var/log/messages")) {
				std::cerr << "Failed to remove record from datafile!" << std::endl;
			}
			// Load data file
			std::cout << "Loading data from new datafile..." << std::endl;
			if (!data.loadData()) {
				std::cerr << "Failed to load data!" << std::endl;
			}
			std::cout << "suspiciousAddresses.size = " << std::to_string(data.suspiciousAddresses.size()) << std::endl;
			// Compare data with iptables
			if (testIptables) {
				std::cout << "Comparing data with iptables..." << std::endl;
				if (!data.checkIptables()) {
					std::cerr << "Failed to compare data with iptables!" << std::endl;
				}
			}
		}

		// Log parsing
		if (testLogParsing) {
			// Reload configuration
			/*std::cout << "Reloading configuration file..." << std::endl;
			if (!cfg.load()){
				std::cerr << "Failed to load configuration!" << std::endl;
			}

			// Reload data
			std::cout << "Reloading datafile..." << std::endl;
			if (!data.loadData()) {
				std::cerr << "Failed to load data!" << std::endl;
			}*/



			// Remove configured log files, add new one for test
			for (itlg = cfg.logGroups.begin(); itlg != cfg.logGroups.end(); ++itlg) {
				itlg->logFiles.clear();
				/*for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
					itlf->bookmark = 0;
					itlf->size = 0;
				}*/
				// Add test log file
				if (itlg->name == "OpenSSH") {
					hb::LogFile logFile;
					logFile.path = "hb/test/test_sshd_log_file";
					logFile.bookmark = 0;
					logFile.size = 0;
					itlg->logFiles.push_back(logFile);
					if (!data.addFile("hb/test/test_sshd_log_file")) {
						std::cerr << "Failed to add new record to datafile!" << std::endl;
					}
					break;
				}
			}

			// Check log files
			std::cout << "Log file check..." << std::endl;
			hb::LogParser lp = hb::LogParser(&log, &cfg, &iptbl, &data);
			lp.checkFiles();

		}

		// Remove temp test datafile
		if ( (testData || testLogParsing) && removeTempData) {
			// Temp datafile name
			cfg.dataFilePath = "test_data_tmp";
			// Remove temporarly data file
			if (std::remove(cfg.dataFilePath.c_str()) != 0) {
				std::cerr << "Failed to remove temporary data file!" << std::endl;
			}
		}

		// Test currently configured log file parsing (not test file like above)
		if (testConfiguredLogParsing) {

			// Default path to config file is /etc/hostblock.conf
			cfg.configPath = "/etc/hostblock.conf";

			// If env variable $HOSTBLOCK_CONFIG is set, then use value from it as path to config
			if (const char* env_cp = std::getenv("HOSTBLOCK_CONFIG")) {
				cfg.configPath = std::string(env_cp);
			}

			// Reload configuration
			std::cout << "Reloading configuration file..." << std::endl;
			if (!cfg.load()){
				std::cerr << "Failed to load configuration!" << std::endl;
			}

			// Use temporarly datafile (empty)
			cfg.dataFilePath = "test_result_datafile";

			// Remove temporarly data file if it exists
			if (std::remove(cfg.dataFilePath.c_str()) != 0) {
				std::cerr << "Failed to remove test result datafile! (it is ok)" << std::endl;
			}

			// Clear suspicious address data
			data.suspiciousAddresses.clear();

			// Reload data
			std::cout << "Loading empty datafile..." << std::endl;
			if (!data.loadData()) {
				std::cerr << "Failed to load data!" << std::endl;
			}

			// Check log files
			std::cout << "Log file check..." << std::endl;
			hb::LogParser lp = hb::LogParser(&log, &cfg, &iptbl, &data);
			lp.checkFiles();
		}

	} catch (std::exception& e){
		std::cerr << e.what() << std::endl;
		end = clock();
		std::cout << "Exec time: " << (double)(end - start)/CLOCKS_PER_SEC << " sec" << std::endl;
		return 1;
	}

	end = clock();
	std::cout << "Exec time: " << (double)(end - start)/CLOCKS_PER_SEC << " sec" << std::endl;
}
