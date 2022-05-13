/*
 * Misc
 */

// Standard string library
#include <string>
// std::locale, std::tolower
#include <locale>
// inet_pton, inet_ntop
#include <arpa/inet.h>
// Header
#include "util.h"

// Hostblock namespace
using namespace hb;

/*
 * Trim spaces from left side of string
 */
std::string Util::ltrim(std::string str)
{
	size_t startpos = str.find_first_not_of(" \t\n\r");
	if (startpos != std::string::npos) {
		return str.substr(startpos);
	}
	return str;
}

/*
 * Trim spaces from right side of string
 */
std::string Util::rtrim(std::string str)
{
	size_t endpos = str.find_last_not_of(" \t\n\r");
	if (endpos != std::string::npos) {
		return str.substr(0, endpos + 1);
	}
	return str;
}

/*
 * Convert characters to lower case
 */
std::string Util::toLower(std::string str)
{
	std::locale loc;
	for (std::string::size_type i=0; i<str.length(); ++i) {
		str[i] = std::tolower(str[i],loc);
	}
	return str;
}

/*
 * Return formatted datetime string
 */
std::string Util::formatDateTime(const time_t rtime, const char* dateTimeFormat)
{
	struct tm* itime = localtime(&rtime);
	char buffer[30];
	strftime(buffer, sizeof(buffer), dateTimeFormat, itime);
	return std::string(buffer);
}

/*
 * Regex error code explanations
 */
std::string Util::regexErrorCode2Text(std::regex_constants::error_type code)
{
	switch(code) {
		case std::regex_constants::error_collate:
			return "The expression contained an invalid collating element name.";
			break;
		case std::regex_constants::error_ctype:
			return "The expression contained an invalid character class name.";
			break;
		case std::regex_constants::error_escape:
			return "The expression contained an invalid escaped character, or a trailing escape.";
			break;
		case std::regex_constants::error_backref:
			return "The expression contained an invalid back reference.";
			break;
		case std::regex_constants::error_brack:
			return "The expression contained mismatched brackets ([ and ]).";
			break;
		case std::regex_constants::error_paren:
			return "The expression contained mismatched parentheses (( and )).";
			break;
		case std::regex_constants::error_brace:
			return "The expression contained mismatched braces ({ and }).";
			break;
		case std::regex_constants::error_badbrace:
			return "The expression contained an invalid range between braces ({ and }).";
			break;
		case std::regex_constants::error_range:
			return "The expression contained an invalid character range.";
			break;
		case std::regex_constants::error_space:
			return "There was insufficient memory to convert the expression into a finite state machine.";
			break;
		case std::regex_constants::error_badrepeat:
			return "The expression contained a repeat specifier (one of *?+{) that was not preceded by a valid regular expression.";
			break;
		case std::regex_constants::error_complexity:
			return "The complexity of an attempted match against a regular expression exceeded a pre-set level.";
			break;
		case std::regex_constants::error_stack:
			return "There was insufficient memory to determine whether the regular expression could match the specified character sequence.";
			break;
		default:
			return "Unknown regex error!";
	}
}

int Util::ipVersion(const std::string ipAddress)
{
	unsigned char buf[sizeof(struct in6_addr)];
	if (inet_pton(AF_INET, ipAddress.c_str(), buf)) {
		return 4;
	} else if (inet_pton(AF_INET6, ipAddress.c_str(), buf)) {
		return 6;
	}
	return -1;
}

std::string Util::ip6Format(const std::string ipAddress)
{
	unsigned char buf[sizeof(struct in6_addr)];
	char str[INET6_ADDRSTRLEN];
	if (inet_pton(AF_INET6, ipAddress.c_str(), buf)) {
		inet_ntop(AF_INET6, buf, str, INET6_ADDRSTRLEN);
	}
	return std::string(str);
}
