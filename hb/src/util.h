/*
 * Misc
 */
#ifndef HBUTIL_H
#define HBUTIL_H

// Vector
#include <vector>
// RegEx
#include <regex>

namespace hb{

enum Report {
	False,
	True,
	NotSet
};

/*
 * Pattern
 */
struct Pattern {
	std::string patternString = "";// Regex as string
	bool portSearch = false;// Whether should search for port in pattern
	std::regex pattern;// Regex to match
	unsigned int score = 1;// Score if pattern matched
	Report abuseipdbReport = Report::NotSet;
	std::vector<unsigned int> abuseipdbCategories;
	std::string abuseipdbComment;
	bool abuseipdbCommentIsSet = false;// Comment is optional, if empty string is set at this level, then do not send comment (do not use comment from global settings)
};

/*
 * Log file
 */
struct LogFile {
	std::string path = "";// Path (config file)
	unsigned long long int bookmark = 0;// Bookmark for seekg (data file)
	unsigned long long int size = 0;// File size when last processed (data file)
	bool dataFileRecord = false;
};

/*
 * Log file group
 */
struct LogGroup {
	std::vector<Pattern> patterns;
	std::vector<Pattern> refusedPatterns;
	std::vector<LogFile> logFiles;
	std::string name = "";
	Report abuseipdbReport = Report::NotSet;
	std::vector<unsigned int> abuseipdbCategories;
	std::string abuseipdbComment;
	bool abuseipdbCommentIsSet = false;// Comment is optional, if empty string is set at this level, then do not send comment (do not use comment from log group or global settings)
};

/*
 * Data about suspicious, whitelisted and blacklisted addresses
 */
struct SuspiciosAddressType{
	unsigned long long int lastActivity = 0;// Should be enough to store timestamp for a very long time
	unsigned int activityScore = 0;
	unsigned int activityCount = 0;
	unsigned int refusedCount = 0;
	bool whitelisted = false;
	bool blacklisted = false;
	bool iptableRule = false;
	unsigned long long int lastReported = 0;
};
struct SuspiciosAddressStatType{
	unsigned long long int lastActivity = 0;
	unsigned int activityScore = 0;
	unsigned int activityCount = 0;
	unsigned int refusedCount = 0;
	std::string address = "";
};

/*
 * Report data for sending to AbuseIPDB
 */
struct ReportToAbuseIPDB {
	std::string ip;
	std::vector<unsigned int> categories;
	std::string comment;
};

/*
 * Report data received from AbuseIPDB
 * Note, comment and userId is returned only with verbose request
 */
struct ReportFromAbuseIPDB {
	std::string ip;
	std::vector<unsigned int> categories;
	unsigned long long int created;
	std::string country;
	std::string isoCode;
	bool isWhitelisted;
	unsigned int score;
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

class Util{
	private:

	public:

		/*
		 * Trim spaces from left side of string
		 */
		static std::string ltrim(std::string str);

		/*
		 * Trim spaces from right side of string
		 */
		static std::string rtrim(std::string str);

		/*
		 * Convert characters to lower case
		 */
		static std::string toLower(std::string str);

		/*
		 * Return formatted datetime string
		 */
		static std::string formatDateTime(const time_t rtime, const char* dateTimeFormat);

		/*
		 * Get textual info about regex error
		 */
		static std::string regexErrorCode2Text(std::regex_constants::error_type code);

};

}

#endif
