/* 
 * Hostblock log writter, simple wrapper for C syslog
 */

// Standard string library
#include <string>
// Syslog
namespace csyslog{
	#include <syslog.h>
}
// Header
#include "logger.h"

// Hostblock namespace
using namespace hb;

Logger::Logger(int facility)
{
	csyslog::openlog("hostblock", LOG_CONS|LOG_PID, facility);
	csyslog::setlogmask(LOG_UPTO(LOG_ERR));
}

Logger::~Logger()
{
	csyslog::closelog();
}

void Logger::setLevel(int level)
{
	csyslog::setlogmask(LOG_UPTO(level));
}

void Logger::info(std::string message)
{
	csyslog::syslog(LOG_INFO, "%s", message.c_str());
}

void Logger::warning(std::string message)
{
	csyslog::syslog(LOG_WARNING, "%s", message.c_str());
}

void Logger::error(std::string message)
{
	csyslog::syslog(LOG_ERR, "%s", message.c_str());
}

void Logger::debug(std::string message)
{
	csyslog::syslog(LOG_DEBUG, "%s", message.c_str());
}
