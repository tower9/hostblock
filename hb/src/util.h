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

/*
 * Pattern
 */
struct Pattern {
	std::string patternString = "";// Regex as string
	std::regex pattern;// Regex to match
	unsigned int score = 1;// Score if pattern matched
};

/*
 * Log file
 */
struct LogFile {
	std::string path = "";// Path (config file)
	unsigned long long int bookmark = 0;// Bookmark for seekg (data file)
	unsigned long long int size = 0;// File size when last processed (data file)
};

/*
 * Log file group
 */
struct LogGroup {
	std::vector<Pattern> patterns;
	std::vector<LogFile> logFiles;
	std::string name = "";
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
		 * Get textual info about regex error
		 */
		static std::string regexErrorCode2Text(std::regex_constants::error_type code);

};

}

#endif
