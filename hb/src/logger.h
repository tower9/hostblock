/*
 * Hostblock log writter, simple wrapper for C syslog
 */

#ifndef HBLOGGER_H
#define HBLOGGER_H

// String
#include <string>

namespace hb{

class Logger{
	private:

	public:

		/*
		 * Constructor
		 */
		Logger(int facility);

		/*
		 * Destructor
		 */
		~Logger();

		/*
		 * Open log
		 */
		void openLog(int facility);

		/*
		 * Close log
		 */
		void closeLog();

		/*
		 * Change log level (syslog priority code for level)
		 */
		void setLevel(int level);

		/*
		 * Log info message
		 */
		void info(std::string message);

		/*
		 * Log warning
		 */
		void warning(std::string message);

		/*
		 * Log error
		 */
		void error(std::string message);

		/*
		 * Debug message
		 */
		void debug(std::string message);
};

}

#endif
