/*
 * Class to work with AbuseIPDB API
 *
 * https://docs.abuseipdb.com/
 */

#ifndef HBABIPDB_H
#define HBABIPDB_H

// Vector
#include <vector>
// Standard string library
#include <string>
// Standard map library
#include <map>
// cURL
#include <curl/curl.h>
// Util
#include "util.h"
// Logger
#include "logger.h"

namespace hb{

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
	EmailSpam = 11,
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

		void init();

		/*
		 * Parse raw headers
		 */
		std::map<std::string, std::string> parseHeaders(std::string& headersRaw);

	public:

		/*
		 * Logger object
		 */
		hb::Logger* log;

		/*
		 * Whether last function call failed with error
		 */
		bool isError = false;

		/*
		 * AbuseIPDB API URL
		 */
		std::string abuseipdbURL = "https://www.abuseipdb.com";

		/*
		 * AbuseIPDB API key
		 */
		std::string abuseipdbKey = "";

		/*
		 * AbuseIPDB API date and time format
		 */
		std::string abuseipdbDatetimeFormat = "%Y-%m-%dT%H:%M:%S";

		/*
		 * Timestamps used to respect AbuseIPDB API limits
		 */
		unsigned int nextCheckTimestamp = 0;// TODO
		unsigned int nextReportTimestamp = 0;
		unsigned int nextBlaclistTimestamp = 0;// TODO

		/*
		 * Constructor
		 */
		AbuseIPDB(hb::Logger* log);
		AbuseIPDB(hb::Logger* log, std::string abuseipdbURL);
		AbuseIPDB(hb::Logger* log, std::string abuseipdbURL, std::string abuseipdbKey);
		AbuseIPDB(hb::Logger* log, std::string abuseipdbURL, std::string abuseipdbKey, std::string abuseipdbDatetimeFormat);

		/*
		 * Deconstructor
		 */
		~AbuseIPDB();

		/*
		 * Check IP address in abuseipdb.com
		 */
		AbuseIPDBCheckResult checkAddress(std::string address, bool verbose = false);

		/*
		 * Report IP address to abuseipdb.com
		 */
		bool reportAddress(std::string address, std::string comment, std::vector<unsigned int> &categories);

		/*
		 * Download blacklist from abuseipdb.com
		 */
		bool getBlacklist(unsigned int confidenceMinimum, unsigned long long int* generatedAt, std::map<std::string, hb::AbuseIPDBBlacklistedAddressType>* blacklist);

		/*
		 * Store cURL response to memmory
		 */
		static size_t SaveCurlDataCallback(void *contents, size_t size, size_t nmemb, void *userp);

};

}

#endif
