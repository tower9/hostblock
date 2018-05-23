/*
 * Log file parser, match patterns with lines in log files
 */

#ifndef HBLOGPARSE_H
#define HBLOGPARSE_H

// Queue
#include <queue>
// Mutex
#include <mutex>
// Util
#include "util.h"
// Logger
#include "logger.h"
// Config
#include "config.h"
// Data
#include "data.h"

namespace hb{

class LogParser{
	private:

		/*
		 * Hostname
		 */
		std::string hostname = "";

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
		 * Data object
		 */
		hb::Data* data;

		/*
		 * Queue for AbuseIPDB reporting
		 */
		std::queue<ReportToAbuseIPDB>* abuseipdbReportingQueue;
		std::mutex* abuseipdbReportingQueueMutex;

		/*
		 * Constructor
		 */
		LogParser(hb::Logger* log, hb::Config* config, hb::Data* data);

		/*
		 * Check all log files for suspicious activity
		 */
		void checkFiles();

};

}

#endif
