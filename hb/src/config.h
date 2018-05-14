/*
 * Class to work with hostblock config file.
 */
#ifndef HBCONFIG_H
#define HBCONFIG_H

// Map
#include <map>
// Vector
#include <vector>
// Standard string library
#include <string>
// Logger
#include "logger.h"
// Util
#include "util.h"

namespace hb{

class Config{
	private:

	public:

		/*
		 * Logger object
		 */
		hb::Logger* log;

		/*
		 * Log level
		 */
		std::string logLevel = "INFO";

		/*
		 * iptables rule to drop packets
		 */
		std::string iptablesRule = "-s %i -j DROP";

		/*
		 * Datetime format
		 */
		std::string dateTimeFormat = "%Y-%m-%d %H:%M:%S";

		/*
		 * Configuration file location
		 */
		std::string configPath = "/etc/hostblock";

		/*
		 * Interval for log file check
		 */
		unsigned int logCheckInterval = 30;

		/*
		 * Needed suspicious activity score to block access (to create iptables rule)
		 */
		unsigned int activityScoreToBlock = 10;

		/*
		 * Score multiplier to calculate for how long time to keep address blocked (result is in seconds)
		 * 0 - will keep forever
		 *
		 * If score == 1:
		 * 1*3600 - hour
		 * 1*86400 - day
		 * 1*432000 - 5 days
		 * 1*2592000 - 30 days
		 *
		 * If score == 4:
		 * 4*3600 - 4 hours
		 * 4*86400 - 4 days
		 * 4*432000 - 20 days
		 * 4*2592000 - 120 days
		 */
		unsigned int keepBlockedScoreMultiplier = 3600;

		/*
		 * Path to data file
		 */
		std::string dataFilePath = "/usr/share/hostblock/hostblock.data";

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
		std::string abuseipdbDatetimeFormat = "%a, %d %b %Y %H:%M:%S";

		/*
		 * Log groups
		 */
		std::vector<hb::LogGroup> logGroups = std::vector<hb::LogGroup>();

		/*
		 * Constructor
		 */
		Config(hb::Logger* log);
		Config(hb::Logger* log, std::string configPath);

		/*
		 * Load configuration from file
		 */
		bool load();

		/*
		 * Process patterns
		 * std::string patternString -> std::regex pattern
		 */
		bool processPatterns();

		/*
		 * Print (stdout) currently loaded config
		 */
		void print();
};

}

#endif
