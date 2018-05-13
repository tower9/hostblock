/*
 * Class to work with hostblock config file.
 */
#ifndef HBABIPDB_H
#define HBABIPDB_H

// Vector
#include <vector>
// Standard string library
#include <string>

namespace hb{

struct AbuseIPDBReport {
	std::string ip;
	std::vector<int> categories;
	unsigned long long int created;
	std::string country;
	std::string isoCode;
	bool isWhitelisted;
	std::string comment;
	int userId;
};

/*
 * AbuseIPDB check function result
 */
struct AbuseIPDBCheckResult {
	std::vector<AbuseIPDBReport> reports;
};

class AbuseIPDB{
	private:

	public:

		/*
		 * Constructor
		 */
		AbuseIPDB();

		/*
		 * Check IP address in abuseipdb.com
		 */
		AbuseIPDBCheckResult checkAddress(std::string address);

		/*
		 * Report IP address to abuseipdb.com
		 */
		bool reportAddress(std::string address, std::string comment, std::vector<int> categories, bool asynchronous = false);

};

}

#endif
