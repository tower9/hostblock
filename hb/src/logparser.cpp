/*
 * Log file parser, match patterns with lines in log files
 * 
 * Some notes, seems that std regex is slower than boost version, maybe worth a switch...
 */

// Standard input/output stream library (cin, cout, cerr, clog)
#include <iostream>
// File stream library (ifstream)
#include <fstream>
// C string
#include <cstring>
// Miscellaneous UNIX symbolic constants, types and functions
namespace cunistd{
	#include <unistd.h>
}
// Linux stat
namespace cstat{
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/stat.h>
}
// Util
#include "util.h"
// Header
#include "logparser.h"

// Hostblock namespace
using namespace hb;

/*
 * Constructor
 */
LogParser::LogParser(hb::Logger* log, hb::Config* config, hb::Data* data)
: log(log), config(config), data(data)
{

}

/*
 * Check all configured log files for suspicious activity
 */
void LogParser::checkFiles()
{
	this->log->debug("Checking log files for suspicious activity...");
	std::vector<hb::LogGroup>::iterator itlg;
	std::vector<hb::LogFile>::iterator itlf;
	std::vector<hb::Pattern>::iterator itlp;
	struct cstat::stat buffer;
	unsigned long long int fileSize = 0;
	unsigned long long int initialBookmark = 0;
	std::string line;
	std::string ipAddress;
	std::regex ipSearchPattern("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
	std::smatch ipSearchResults;
	time_t currentTime, lastInfo;
	time(&currentTime);
	lastInfo = currentTime;
	unsigned long long int jobTotal = 0, jobDone = 0;
	float jobPercentage = 0;

	// Loop log groups
	for (itlg = this->config->logGroups.begin(); itlg != this->config->logGroups.end(); ++itlg) {
		this->log->debug("Checking log group: " + itlg->name);

		// Loop log files in each group
		for (itlf = itlg->logFiles.begin(); itlf != itlg->logFiles.end(); ++itlf) {
			this->log->debug("Checking log file: " + itlf->path);

			// Simple log rotation check (based on file size change)
			if (cstat::stat(itlf->path.c_str(), &buffer) == 0) {
				fileSize = (intmax_t)buffer.st_size;
				if (fileSize < itlf->size) {
					itlf->bookmark = 0;
					this->log->warning("Last known size reset for " + itlf->path);
					this->data->updateFile(itlf->path);
				}
				this->log->debug("Current size: " + std::to_string(fileSize) + " Last known size: " + std::to_string(itlf->size));
			} else {
				this->log->error("Unable to open file " + itlf->path + "! " + std::to_string(errno) + ": " + std::string(strerror(errno)));
				continue;
			}

			// Check log file
			std::ifstream is(itlf->path, std::ifstream::binary);
			if (is && is.is_open()) {
				// Seek to last known position
				is.seekg(itlf->bookmark, is.beg);

				// For comparision after log check to see if bookmark has changed and datafile needs to be updated
				initialBookmark = itlf->bookmark;

				// Calculate total job to do
				jobTotal = fileSize - initialBookmark;

				// Read new lines until end of file
				while (std::getline(is, line)) {

					// Match patterns
					for (itlp = itlg->patterns.begin(); itlp != itlg->patterns.end(); ++itlp) {
						try {

							// Match line with pattern
							if (std::regex_match(line, itlp->pattern)) {

								// Get IP address out of line
								if (std::regex_search(line, ipSearchResults, ipSearchPattern)) {
									if (ipSearchResults.size() > 0) {

										// Optimistically, here we hope that first match is the address we need
										ipAddress = std::string(ipSearchResults[0]);
										this->log->debug("Suspicious activity pattern match! Address: " + ipAddress + " Score: " + std::to_string(itlp->score));

										// Update address data
										this->data->saveActivity(ipAddress, itlp->score, 1, 0);
									}
								}
								this->log->debug("Pattern: " + itlp->patternString);
							}

						} catch (std::regex_error& e) {
							std::string message = e.what();
							this->log->error(message + ": " + std::to_string(e.code()));
							this->log->error(hb::Util::regexErrorCode2Text(e.code()));
						}
					}

					// Check refused patterns
					for (itlp = itlg->refusedPatterns.begin(); itlp != itlg->refusedPatterns.end(); ++itlp) {
						try {

							// Match line with pattern
							if (std::regex_match(line, itlp->pattern)) {

								// Get IP address out of line
								if (std::regex_search(line, ipSearchResults, ipSearchPattern)) {
									if (ipSearchResults.size() > 0) {

										// Optimistically, here we hope that first match is address we need
										ipAddress = std::string(ipSearchResults[0]);
										this->log->debug("Blocked access pattern match! Address: " + ipAddress + " Score: " + std::to_string(itlp->score));

										// Update address data
										if (this->data->suspiciousAddresses.count(ipAddress) > 0) {
											this->data->saveActivity(ipAddress, itlp->score, 0, 1);
										} else {
											this->log->debug("Matched blocked access pattern, but no previous information about suspicious activity, skipping...");
										}
									}
								}
								this->log->debug("Pattern: " + itlp->patternString);
							}

						} catch (std::regex_error& e) {
							std::string message = e.what();
							this->log->error(message + ": " + std::to_string(e.code()));
							this->log->error(hb::Util::regexErrorCode2Text(e.code()));
						}
					}

					// Update bookmark
					itlf->bookmark = is.tellg();

					// TODO Check log rotation after each 500 lines (this process can be long running)
					// if (cstat::stat(itlf->path.c_str(), &buffer) == 0) {

					// }

					// TODO Respond on daemon main loop quit request
					// if (!running) {
					// 	// Update datafile
					// 	if (initialBookmark != itlf->bookmark) {
					// 		this->data->updateFile(itlf->path);
					// 	}
					// 	// Break the loop
					// 	break;
					// }

					// Sleep
					cunistd::usleep(10);

					// Output some info to log file each min
					time(&currentTime);
					if (currentTime - lastInfo >= 60) {
						jobDone = itlf->bookmark - initialBookmark;
						jobPercentage = (float)jobDone * 100 / (float)jobTotal;
						this->log->info("Processing " + itlf->path + ", progress: " + std::to_string(jobPercentage) + "%");
						lastInfo = currentTime;
					}
				}
				this->log->debug("Finished reading until end of file, pos: " + std::to_string(itlf->bookmark));

				// Close file
				is.close();

				// Update last known file size
				itlf->size = fileSize;

				// Update datafile
				if (initialBookmark != itlf->bookmark) {
					this->data->updateFile(itlf->path);
				}
			} else {
				this->log->error("Unable to open file " + itlf->path + " for reading!");
				continue;
			}

		}
	}
}
