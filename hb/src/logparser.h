/*
 * Log file parser, match patterns with lines in log files
 */

#ifndef HBLOGPARSE_H
#define HBLOGPARSE_H

// Logger
#include "logger.h"
// Config
#include "config.h"
// Iptables
#include "iptables.h"
// Data
#include "data.h"

namespace hb{

class LogParser{
	private:

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
		 * Iptables object
		 */
		hb::Iptables* iptables;

		/*
		 * Data object
		 */
		hb::Data* data;

		/*
		 * Constructor
		 */
		LogParser(hb::Logger* log, hb::Config* config, hb::Iptables* iptables, hb::Data* data);

		/*
		 * Check all log files for suspicious activity
		 */
		void checkFiles();

};

}

#endif
