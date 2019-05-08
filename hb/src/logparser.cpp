/*
 * Log file parser, match patterns with lines in log files
 *
 * Some notes, seems that std regex is slower than boost version, maybe worth to switch...
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
LogParser::LogParser(hb::Logger* log, hb::Config* config, hb::Data* data, std::queue<ReportToAbuseIPDB>* abuseipdbReportingQueue, std::mutex* abuseipdbReportingQueueMutex)
: log(log), config(config), data(data), abuseipdbReportingQueue(abuseipdbReportingQueue), abuseipdbReportingQueueMutex(abuseipdbReportingQueueMutex)
{
	char hname[1024];
	hname[1023] = '\0';
	cunistd::gethostname(hname, 1023);
	this->hostname = std::string(hname);
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
	std::string ipAddress, port;
	std::smatch patternMatchResults;
	time_t currentTime, lastInfo;
	time(&currentTime);
	lastInfo = currentTime;
	unsigned long long int jobTotal = 0, jobDone = 0;
	float jobPercentage = 0;
	bool sendReport = false;
	ReportToAbuseIPDB reportToSend;
	std::vector<unsigned int> reportCategories;
	std::string reportComment = "";
	std::size_t posc, posh;
	std::map<std::string, hb::SuspiciosAddressType>::iterator itsa;
	std::string currentTimeFormatted = Util::formatDateTime((const time_t)currentTime, this->config->dateTimeFormat.c_str());

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

							/*
							 * Match line with pattern
							 * Note, using regex groups to get IP address and port
							 * http://www.cplusplus.com/reference/regex/ECMAScript/#groups
							 * Match results:
							 *   index 0 - whole match
							 *   index 1 - IP address
							 *   index 2 - port (optional)
							 */
							if (std::regex_match(line, patternMatchResults, itlp->pattern)) {
								if (patternMatchResults.size() > 1) {

									// IP address
									ipAddress = std::string(patternMatchResults[1]);
									this->log->debug("Suspicious acitivity pattern match! Address: " + ipAddress + " Score: " + std::to_string(itlp->score));
									// TODO check that this result is actually an IP address

									// Port
									if (itlp->portSearch) {
										if (patternMatchResults.size() > 2) {
											port = std::string(patternMatchResults[2]);
											// TODO check that this regex result is actually a port (0 - 65535)
										} else {
											this->log->warning("Port search is specified in pattern, but was not found in matched line!");
											port = "";
										}
									}

									// Update address data
									this->data->saveActivity(ipAddress, itlp->score, 1, 0);

									// Check whether need to send report about match
									sendReport = false;
									reportCategories.clear();
									reportComment = "";
									if (this->config->abuseipdbKey.size() > 0) {
										// Need to send if have global setting
										if (this->config->abuseipdbReportAll) {
											sendReport = true;
										}
										reportCategories = this->config->abuseipdbDefaultCategories;
										if (this->config->abuseipdbDefaultCommentIsSet) {
											reportComment = this->config->abuseipdbDefaultComment;
										}
										// Log group setting overrides global setting
										if (itlg->abuseipdbReport == Report::True) {
											sendReport = true;
										} else if (itlg->abuseipdbReport == Report::False) {
											sendReport = false;
										}
										if (itlg->abuseipdbCategories.size() > 0) {
											reportCategories = itlg->abuseipdbCategories;
										}
										if (itlg->abuseipdbCommentIsSet) {
											reportComment = itlg->abuseipdbComment;
										}
										// Pattern setting overrides log group setting
										if (itlp->abuseipdbReport == Report::True) {
											sendReport = true;
										} else if (itlp->abuseipdbReport == Report::False) {
											sendReport = false;
										}
										if (itlp->abuseipdbCategories.size() > 0) {
											reportCategories = itlp->abuseipdbCategories;
										}
										if (itlp->abuseipdbCommentIsSet) {
											reportComment = itlp->abuseipdbComment;
										}
									}

									// Do not report whitelisted addresses
									if (this->data->suspiciousAddresses.count(ipAddress) > 0 && this->data->suspiciousAddresses[ipAddress].whitelisted) {
										sendReport = false;
									}

									// Check whether 15 minutes are passed since last report
									// TODO implement config parameter and use 15 minutes as min with default 1h
									if (sendReport) {
										if (this->data->suspiciousAddresses.count(ipAddress) > 0) {
											if (currentTime - this->data->suspiciousAddresses[ipAddress].lastReported < 900) {
												this->log->debug("Not enqueuing report about " + ipAddress + " more often than each 15 minutes!");
												sendReport = false;
											} else {
												this->data->suspiciousAddresses[ipAddress].lastReported = currentTime;
												// this->data->updateAddress(ipAddress);
											}
										} else {
											this->log->warning("Need to send report about address " + ipAddress + ", but data about it is not found in data file! Skipping!");
											sendReport = false;
										}
									}

									// Search for %i, %p and %m placeholders in comment and replace with data if needed
									if (sendReport) {
										posc = reportComment.find("%i");
										if (posc != std::string::npos) {
											reportComment = reportComment.replace(posc, 2, ipAddress);
										}
										posc = reportComment.find("%p");
										if (posc != std::string::npos) {
											if (itlp->portSearch) {
												reportComment = reportComment.replace(posc, 2, port);
											} else {
												this->log->warning("Comment template contains port placeholder, but port is not found in matched line! Adjust pattern or comment to avoid this warning!");
											}
										}
										posc = reportComment.find("%m");
										if (posc != std::string::npos) {
											if (this->config->abuseipdbReportMask) {
												// TODO put in loop, there can be multiple occurrences
												posh = line.find(this->hostname);
												if (posh != std::string::npos) {
													reportComment = reportComment.replace(posc, 2, line.substr(0, posh) + std::string(this->hostname.length(), '*') + line.substr(posh + this->hostname.length()));
												} else {
													reportComment = reportComment.replace(posc, 2, line);
												}
											} else {
												reportComment = reportComment.replace(posc, 2, line);
											}
										}
										posc = reportComment.find("%d");
										if (posc != std::string::npos) {
											reportComment = reportComment.replace(posc, 2, currentTimeFormatted);
										}
									}

									// Strip comment to 1500 characters
									if (sendReport) {
										if (reportComment.length() > 1500) {
											reportComment = reportComment.substr(0, 1500);
											this->log->warning("Comment for AbuseIPDB report is too long, length was reduced by removing characters from end!");
										}
									}

									// Put report into queue for sending to AbuseIPDB
									if (sendReport) {
										ReportToAbuseIPDB reportToSend;
										reportToSend.ip = ipAddress;
										reportToSend.categories = reportCategories;
										reportToSend.comment = reportComment;
										this->abuseipdbReportingQueueMutex->lock();
										this->abuseipdbReportingQueue->push(reportToSend);
										this->abuseipdbReportingQueueMutex->unlock();
										this->log->debug("Information about " + ipAddress + " is put into queue for sending to AbuseIPDB...");
									}

									this->log->debug("Match with pattern: " + itlp->patternString);

									// Line matched with suspicious activity pattern, break the loop
									break;
								}

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

							/*
							 * Match line with pattern
							 * Note, using regex groups to get IP address and port
							 * http://www.cplusplus.com/reference/regex/ECMAScript/#groups
							 * Match results:
							 *   index 0 - whole match
							 *   index 1 - IP address
							 *   index 2 - port (optional)
							 */
							if (std::regex_match(line, patternMatchResults, itlp->pattern)) {
								if (patternMatchResults.size() > 1) {

									// IP address
									ipAddress = std::string(patternMatchResults[1]);
									this->log->debug("Blocked access pattern match! Address: " + ipAddress + " Score: " + std::to_string(itlp->score));
									// TODO check that this result is actually an IP address

									// Port
									if (itlp->portSearch) {
										if (patternMatchResults.size() > 2) {
											port = std::string(patternMatchResults[2]);
											// TODO check that this regex result is actually a port (0 - 65535)
										} else {
											this->log->warning("Port search is specified in pattern, but was not found in matched line!");
											port = "";
										}
									}

									// Update address data
									if (this->data->suspiciousAddresses.count(ipAddress) > 0 || this->data->abuseIPDBBlacklist.count(ipAddress) > 0) {
										this->data->saveActivity(ipAddress, itlp->score, 0, 1);

										// Check whether need to send report about match
										sendReport = false;
										reportCategories.clear();
										reportComment = "";
										if (this->config->abuseipdbKey.size() > 0) {
											// Need to send if have global setting
											if (this->config->abuseipdbReportAll) {
												sendReport = true;
											}
											reportCategories = this->config->abuseipdbDefaultCategories;
											if (this->config->abuseipdbDefaultCommentIsSet) {
												reportComment = this->config->abuseipdbDefaultComment;
											}
											// Log group setting overrides global setting
											if (itlg->abuseipdbReport == Report::True) {
												sendReport = true;
											} else if (itlg->abuseipdbReport == Report::False) {
												sendReport = false;
											}
											if (itlg->abuseipdbCategories.size() > 0) {
												reportCategories = itlg->abuseipdbCategories;
											}
											if (itlg->abuseipdbCommentIsSet) {
												reportComment = itlg->abuseipdbComment;
											}
											// Pattern setting overrides log group setting
											if (itlp->abuseipdbReport == Report::True) {
												sendReport = true;
											} else if (itlp->abuseipdbReport == Report::False) {
												sendReport = false;
											}
											if (itlp->abuseipdbCategories.size() > 0) {
												reportCategories = itlp->abuseipdbCategories;
											}
											if (itlp->abuseipdbCommentIsSet) {
												reportComment = itlp->abuseipdbComment;
											}
										}

										// Do not report whitelisted addresses
										if (this->data->suspiciousAddresses.count(ipAddress) > 0 && this->data->suspiciousAddresses[ipAddress].whitelisted) {
											sendReport = false;
										}

										// Check whether 15 minutes are passed since last report
										// TODO implement config parameter and use 15 minutes as min with default 1h
										if (sendReport) {
											if (this->data->suspiciousAddresses.count(ipAddress) > 0) {
												if (currentTime - this->data->suspiciousAddresses[ipAddress].lastReported < 900) {
													this->log->debug("Not enqueuing report about " + ipAddress + " more often than each 15 minutes!");
													sendReport = false;
												} else {
													this->data->suspiciousAddresses[ipAddress].lastReported = currentTime;
													// this->data->updateAddress(ipAddress);
												}
											} else {
												this->log->warning("Need to send report about address " + ipAddress + ", but data about it is not found in data file! Skipping!");
												sendReport = false;
											}
										}

										// Search for %i, %p and %m placeholders in comment and replace with data if needed
										if (sendReport) {
											posc = reportComment.find("%i");
											if (posc != std::string::npos) {
												reportComment = reportComment.replace(posc, 2, ipAddress);
											}
											posc = reportComment.find("%p");
											if (posc != std::string::npos) {
												if (itlp->portSearch) {
													reportComment = reportComment.replace(posc, 2, port);
												} else {
													this->log->warning("Comment template contains port placeholder, but port is not found in matched line! Adjust pattern or comment to avoid this warning!");
												}
											}
											posc = reportComment.find("%m");
											if (posc != std::string::npos) {
												if (this->config->abuseipdbReportMask) {
													// TODO put in loop, there can be multiple occurrences
													posh = line.find(this->hostname);
													if (posh != std::string::npos) {
														reportComment = reportComment.replace(posc, 2, line.substr(0, posh) + std::string(this->hostname.length(), '*') + line.substr(posh + this->hostname.length()));
													} else {
														reportComment = reportComment.replace(posc, 2, line);
													}
												} else {
													reportComment = reportComment.replace(posc, 2, line);
												}
											}
											posc = reportComment.find("%d");
											if (posc != std::string::npos) {
												reportComment = reportComment.replace(posc, 2, currentTimeFormatted);
											}
										}

										// Strip comment to 1500 characters
										if (sendReport) {
											if (reportComment.length() > 1500) {
												reportComment = reportComment.substr(0, 1500);
												this->log->warning("Comment for AbuseIPDB report is too long, length was reduced by removing characters from end!");
											}
										}

										// Put report into queue for sending to AbuseIPDB
										if (sendReport) {
											ReportToAbuseIPDB reportToSend;
											reportToSend.ip = ipAddress;
											reportToSend.categories = reportCategories;
											reportToSend.comment = reportComment;
											this->abuseipdbReportingQueueMutex->lock();
											this->abuseipdbReportingQueue->push(reportToSend);
											this->abuseipdbReportingQueueMutex->unlock();
											this->log->debug("Information about " + ipAddress + " is put into queue for sending to AbuseIPDB...");
										}
									} else {
										this->log->warning("Matched blocked access pattern, but no previous information about suspicious activity, skipping...");
									}

									this->log->debug("Match with pattern: " + itlp->patternString);

									// Line matched with blocked access pattern, break the loop
									break;
								}

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
