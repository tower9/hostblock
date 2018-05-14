/*
 * Class to work with AbuseIPDB API
 */
#ifndef HBABIPDB_H
#define HBABIPDB_H

// Vector
#include <vector>
// Standard string library
#include <string>

namespace hb{

/*
 * AbuseIPDB report
 * Note, comment and userId is returned with verbose request
 */
struct AbuseIPDBReport {
	std::string ip;
	std::vector<unsigned int> categories;
	unsigned long long int created;
	std::string country;
	std::string isoCode;
	bool isWhitelisted;
	std::string comment;
	unsigned int userId;
};

/*
 * To store JSON result from abuseipdb.com with cURL
 */
struct AbuseIPDBJSONData {
	char *memory;
	size_t size;
};

/*
 * AbuseIPDB report categories
 */
enum AbuseIPDBCategories {
	FraudOrders = 3,
	DDoSAttach = 4,
	FTPBruteForce = 5,
	PingOfDeath = 6,
	Phishing = 7,
	FraudVoIP = 8,
	OpenProxy = 9,
	WebSpam = 10,
	EmailSPam = 11,
	BlogSpam = 12,
	VPNIP = 13,
	PortScan = 14,
	Hacking = 15,
	SQLInjection = 16,
	Spoofing = 17,
	BruteForce = 18,
	BadWebBot = 19,
	ExploitedHost = 20,
	WebAppAttack = 21,
	SSH = 22,
	IoTTargeted = 23
};

class AbuseIPDB{
	private:
		/*
		 * cURL
		 */
		CURL* curl;

	public:

		/*
		 * Logger object
		 */
		hb::Logger* log;

		/*
		 * Config object
		 */
		hb::Config* config;

		/*
		 * Constructor
		 */
		AbuseIPDB(hb::Logger* log, hb::Config* config);

		/*
		 * Deconstructor
		 */
		~AbuseIPDB();

		/*
		 * Check IP address in abuseipdb.com
		 */
		std::vector<AbuseIPDBReport> checkAddress(std::string address, bool verbose = false);

		/*
		 * Report IP address to abuseipdb.com
		 */
		bool reportAddress(std::string address, std::string comment, std::vector<unsigned int> &categories);

		/*
		 * For cURL response store
		 */
		static size_t SaveJSONResultCallback(void *contents, size_t size, size_t nmemb, void *userp);

};

}

#endif
