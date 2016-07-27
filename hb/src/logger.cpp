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

/*
 * Constructor
 */
Logger::Logger(int facility)
{
	csyslog::openlog("hostblock", LOG_CONS|LOG_PID, facility);
	csyslog::setlogmask(LOG_UPTO(LOG_INFO));
}

/*
 * Destructor
 */
Logger::~Logger()
{
	csyslog::closelog();
}

/*
 * Open log
 */
void Logger::openLog(int facility)
{
	csyslog::openlog("hostblock", LOG_CONS|LOG_PID, facility);
}

/*
 * Close log
 */
void Logger::closeLog()
{
	csyslog::closelog();
}

/*
 * Change log level (syslog priority code for level)
 */
void Logger::setLevel(int level)
{
	csyslog::setlogmask(LOG_UPTO(level));
}

/*
 * Log info message
 */
void Logger::info(std::string message)
{
	csyslog::syslog(LOG_INFO, "%s", message.c_str());
}

/*
 * Log warning
 */
void Logger::warning(std::string message)
{
	csyslog::syslog(LOG_WARNING, "%s", message.c_str());
}

/*
 * Log error
 */
void Logger::error(std::string message)
{
	csyslog::syslog(LOG_ERR, "%s", message.c_str());
}

/*
 * Debug message
 */
void Logger::debug(std::string message)
{
	csyslog::syslog(LOG_DEBUG, "%s", message.c_str());
}
