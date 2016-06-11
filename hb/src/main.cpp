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
// C getopt
namespace cgetopt{
	#include <getopt.h>
}
// Syslog
namespace csyslog{
	#include <syslog.h>
}
// Logger
#include "logger.h"
// Iptables
#include "iptables.h"
// Config
#include "config.h"
// Data
#include "data.h"

/*
 * Output short help
 */
void printUsage()
{
	std::cout << "Hostblock v.2.0" << std::endl << std::endl;
	std::cout << "hostblock [-h | --help] [-s | --statistics] [-l | --list [-c | --count] [-t | --time]] [-r<ip_address> | --remove=<ip_address>] [-d | --daemon]" << std::endl << std::endl;
	std::cout << " -h             | --help                - this information" << std::endl;
	std::cout << " -s             | --statistics          - statistics" << std::endl;
	std::cout << " -l             | --list                - list of suspicious IP addresses" << std::endl;
	std::cout << " -lc            | --list --count        - list of suspicious IP addresses with suspicious activity count" << std::endl;
	std::cout << " -lt            | --list --time         - list of suspicious IP addresses with last suspicious activity time" << std::endl;
	std::cout << " -lct           | --list --count --time - list of suspicious IP addresses with suspicious activity count and last suspicious activity time" << std::endl;
	std::cout << " -r<IP address> | --remove=<IP address> - remove IP address from data file" << std::endl;
	std::cout << " -d             | --daemon              - run as daemon" << std::endl;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printUsage();
		exit(0);
	}
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
		hb::Data data = hb::Data(&log, &config);

		// Load datafile
		if (!data.loadData()) {
			std::cerr << "Failed to load data!" << std::endl;
			exit(1);
		}

		if (statisticsFlag) {// Output statistics

			exit(0);
		} else if (listFlag) {// Output list of suspicious addresses

			exit(0);
		} else if (removeFlag) {// Remove address from datafile

			exit(0);
		} else if (daemonFlag) {// Run as daemon
			log.openLog(LOG_DAEMON);

			exit(0);
		} else {
			printUsage();
			exit(0);
		}
}