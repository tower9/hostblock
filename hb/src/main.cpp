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
				// Statistics option
				break;
			case 'l':
				// List option
				break;
			case 'c':
				// Count option
				break;
			case 't':
				// Time option
				break;
			case 'r':
				// Address remove option
				break;
			case 'd':
				// Daemon option
				break;
			default:
				printUsage();
				exit(0);
		}

}