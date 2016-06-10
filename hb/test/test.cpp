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

int main(int argc, char *argv[])
{
	clock_t start = clock();
	clock_t end;

	bool testSyslog = false;
	bool testIptables = false;
	bool testConfig = false;
	bool testData = true;

	try{
		// Syslog
		std::cout << "Creating Logger object..." << std::endl;
		hb::Logger log = hb::Logger(LOG_USER);
		if (testSyslog){
			std::cout << "Writting to syslog with level LOG_USER..." << std::endl;
			log.info("Syslog test - level: LOG_USER msg type: info");
			log.warning("Syslog test - level: LOG_USER msg type: warning");
			log.error("Syslog test - level: LOG_USER msg type: error");
			log.debug("Syslog test - level: LOG_USER msg type: debug");
			log.setLevel(LOG_DAEMON);
			std::cout << "Writting to syslog with level LOG_DAEMON..." << std::endl;
			log.info("Syslog test - level: LOG_DAEMON msg type: info");
			log.warning("Syslog test - level: LOG_DAEMON msg type: warning");	
			log.error("Syslog test - level: LOG_DAEMON msg type: error");
			log.debug("Syslog test - level: LOG_DAEMON msg type: debug");
			log.setLevel(LOG_DEBUG);
			std::cout << "Writting to syslog with level LOG_DEBUG..." << std::endl;
			log.info("Syslog test - level: LOG_DEBUG msg type: info");
			log.warning("Syslog test - level: LOG_DEBUG msg type: warning");
			log.error("Syslog test - level: LOG_DEBUG msg type: error");
			log.debug("Syslog test - level: LOG_DEBUG msg type: debug");
		}
		log.setLevel(LOG_DEBUG);

		// iptables
		if (testIptables){
			std::cout << "Creating Iptables object..." << std::endl;
			hb::Iptables iptbl = hb::Iptables();
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
		hb::Data data = hb::Data(&log, &cfg);
		cfg.dataFilePath = "hb/test/test_data";
		std::cout << "Loading data..." << std::endl;
		if (!data.loadData()) {
			std::cerr << "Failed to load data!" << std::endl;
		}
		if (testData){
			// Create new data file
			std::cout << "Creating new data file..." << std::endl;
			cfg.dataFilePath = "test_data_tmp";
			if (!data.saveData()) {
				std::cerr << "Failed to save data to datafile!" << std::endl;
			}
			std::cout << "suspiciousAddresses.size = " << std::to_string(data.suspiciousAddresses.size()) << std::endl;
			// std::map<std::string, hb::SuspiciosAddressType> suspiciousAddressesOrig = data.suspiciousAddresses;
			// Load newly created data file
			std::cout << "Loading data from new datafile..." << std::endl;
			if (!data.loadData()) {
				std::cerr << "Failed to load data!" << std::endl;
			}
			std::cout << "suspiciousAddresses.size = " << std::to_string(data.suspiciousAddresses.size()) << std::endl;
			// Remove newly created data file
			if (std::remove(cfg.dataFilePath.c_str()) != 0) {
				std::cerr << "Failed to remove temporary data file!" << std::endl;
			}
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
