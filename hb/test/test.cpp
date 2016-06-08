// Standard input/output stream library (cin, cout, cerr, clog)
#include <iostream>
// Time (clock_t, clock())
#include <time.h>
// Syslog
namespace csyslog{
	#include <syslog.h>
}
// Logger
#include "../src/logger.h"

int main(int argc, char *argv[])
{
	clock_t start = clock();
	clock_t end;

	bool testSyslog = true;

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
	} catch (std::exception& e){
		std::cerr << e.what() << std::endl;
		end = clock();
		std::cout << "Exec time: " << (double)(end - start)/CLOCKS_PER_SEC << " sec" << std::endl;
		return 1;
	}

	end = clock();
	std::cout << "Exec time: " << (double)(end - start)/CLOCKS_PER_SEC << " sec" << std::endl;
}