/*
 * Class to work with AbuseIPDB API
 *
 */

// Standard input/output stream library (cin, cout, cerr, clog, etc)
#include <iostream>
// Vector
#include <vector>
// Standard string library
#include <string>
// String stream
#include <sstream>
// Standard map library
#include <map>
// (get_time, put_time)
#include <iomanip>
// Date and time manipulation
#include <chrono>
// memcpy
#include <cstring>
// Definition for network database operations (NI_MAXHOST, NI_NUMERICHOST)
#include <netdb.h>
// Declarations for getting network interface addresses (getifaddrs, freeifaddrs)
#include <ifaddrs.h>
// Miscellaneous UNIX symbolic constants, types and functions
namespace cunistd{
	#include <unistd.h>
}
// cURL
#include <curl/curl.h>
// libjsoncpp1
#include <jsoncpp/json/json.h>
// Logger
#include "logger.h"
// Header
#include "abuseipdb.h"

// Hostblock namespace
using namespace hb;

AbuseIPDB::AbuseIPDB(hb::Logger* log, hb::Config* config)
: log(log), config(config)
{
	this->init();
}

void AbuseIPDB::init()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	this->curl = curl_easy_init();

	int s;

	// Get hostname
	char hname[HOST_NAME_MAX];
	std::string hostname;
	s = cunistd::gethostname(hname, HOST_NAME_MAX);
	if (s != 0) {
		this->log->warning("Failed to get host name to use for AbuseIPDB report masking! gethostname() returned " + std::to_string(errno) + ": " + std::string(strerror(errno)));
	} else {
		hostname = std::string(hname);
		this->stringsToMask.push_back(hostname);
		this->log->debug("Hostname to mask: " + hostname);
		std::size_t pos = hostname.find(".");
		if (pos != std::string::npos) {
			// If . is in hostname, then most likely we previously got FQDN, add first part of FQDN also to hostnames vector for masking
			hostname = hostname.substr(0, pos);
			this->stringsToMask.push_back(hostname);
			this->log->debug("Hostname to mask: " + hostname);
		}
	}

	// Get IP addresses
	struct ifaddrs *addrs, *ap;
	int family;
	char addr[NI_MAXHOST];
	std::string ipAddress;
	s = getifaddrs(&addrs);
	if (s != 0) {
		this->log->warning("Failed to get IP addresses to use for AbuseIPDB report masking! getifaddrs() returned " + std::to_string(s) + ": " + std::string(gai_strerror(s)));
	} else {
		for (ap = addrs; ap != NULL; ap = ap->ifa_next) {
			if (ap->ifa_addr == NULL) {
				continue;
			}
			family = ap->ifa_addr->sa_family;
			if (family == AF_INET || family == AF_INET6) {
				s = getnameinfo(ap->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				if (s != 0) {
					this->log->warning("Failed to get IP addresses to use for AbuseIPDB report masking! getnameinfo() returned: " + std::to_string(s) + ": " + std::string(gai_strerror(s)));
				} else {
					ipAddress = std::string(addr);
					if (family == AF_INET6) {
						std::size_t posc = ipAddress.find("%");
						if (posc != std::string::npos) {
							ipAddress = ipAddress.substr(0, posc);
						}
					}
					this->stringsToMask.push_back(ipAddress);
					this->log->debug("IP address to mask: " + ipAddress);
				}
			}
		}
		freeifaddrs(addrs);
	}
}

AbuseIPDB::~AbuseIPDB()
{
	curl_global_cleanup();
}

std::map<std::string, std::string> AbuseIPDB::parseHeaders(std::string& headersRaw)
{
	std::map<std::string, std::string> result;
	std::size_t pos;
	std::string line, key, value;
	std::istringstream ss(headersRaw);
	while (std::getline(ss, line)) {
		pos = line.find_first_of(":");
		if (pos != std::string::npos) {
			key = hb::Util::rtrim(hb::Util::ltrim(line.substr(0, pos)));
			value = hb::Util::rtrim(hb::Util::ltrim(line.substr(pos + 1)));
			if (key.length() > 0) {
				result.insert(std::pair<std::string, std::string>(key, value));
			}
		}
	}
	return result;
}

AbuseIPDBCheckResult AbuseIPDB::checkAddress(std::string address, bool verbose)
{
	AbuseIPDBCheckResult result;
	this->isError = false;

	// API key is mandatory
	if (this->config->abuseipdbKey.size() == 0) {
		this->isError = true;
		this->log->error("Cannot call AbuseIPDB API, API key is not provided!");
	}

	if (this->isError == false) {
		// Init some memory where JSON response will be stored
		CurlData chunk;
		chunk.memory = (char*)malloc(1); // Will be extended with realloc later
		chunk.size = 0; // No data yet
		CURLcode res;// cURL response code
		struct curl_slist *headers=NULL;// Init to NULL is important

		// Prepare URL, header and request parameters
		std::string url = this->config->abuseipdbURL;
		headers = curl_slist_append(headers, "Accept: application/json");
		headers = curl_slist_append(headers, ("Key: " + this->config->abuseipdbKey).c_str());
		url += "/api/v2/check";
		std::string requestParams = "ipAddress=" + address;
		requestParams += "&maxAgeInDays=7";
		if (verbose) {
			requestParams += "&verbose";
		}

		// Init curl
		this->curl = curl_easy_init();

		if (this->curl) {
			// Set header
			curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, headers);

			// Store results using callback function
			curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveCurlDataCallback);

			// Store results into CurlData
			curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&chunk);

			// User agent
			curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
			std::string userAgent = "Hostblock/";
			userAgent += kHostblockVersion;
			userAgent += " libcurl/";
			userAgent += versionData->version;
			curl_easy_setopt(this->curl, CURLOPT_USERAGENT, userAgent.c_str());

			// URL and request parameters
			curl_easy_setopt(this->curl, CURLOPT_URL, (url + "?" + requestParams).c_str());

			// HTTP/HTTPs call
			this->log->debug("Calling " + url);
			this->log->debug("Data: " + requestParams);
			res = curl_easy_perform(this->curl);

			if (res != CURLE_OK) {
				this->isError = true;
				this->log->error("Failed to call AbuseIPDB API address check service! curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
			} else {
				// Get HTTP status code
				long httpCode;
				curl_easy_getinfo(this->curl, CURLINFO_RESPONSE_CODE, &httpCode);
				this->log->debug("Response received! HTTP status code: " + std::to_string(httpCode));

				// Must have http status code 200
				if (httpCode != 200) {
					this->isError = true;
					this->log->error("Failed to call AbuseIPDB API address check service! HTTP status code: " + std::to_string(httpCode));
				} else {
					this->log->debug("Received data size: " + std::to_string(chunk.size));

					// Convert to string for libjson
					unsigned int i, j;
					std::string response = "";
					for (i = 0; i < chunk.size; ++i) {
						response += chunk.memory[i];
					}
					// std::cout << "Response: " << response << std::endl;

					// Parse JSON and store into hb::AbuseIPDBCheckResult
					Json::Reader reader;
					Json::Value obj;
					std::tm t = {};
					std::time_t timestamp;
					std::time(&timestamp);
					if (reader.parse(response, obj)) {
						// std::cout << "count: " << obj.size() << std::endl;
						if (obj.size() > 0) {
							// IP address
							result.ipAddress = obj["data"]["ipAddress"].asString();

							// True if address is from public (internet) range or false if address is from private (LAN) range
							result.isPublic = true;
							if (obj["data"]["isPublic"].asString() == "false") {
								result.isPublic = false;
							}

							// IP address version
							result.ipVersion = obj["data"]["ipVersion"].asUInt();

							// Whether address is in AbuseIPDB whitelist
							result.isWhitelisted = false;
							if (obj["data"]["isWhitelisted"].asString() == "true") {
								result.isWhitelisted = true;
							}

							// AbuseIPDB confidence score
							result.abuseConfidenceScore = obj["data"]["abuseConfidenceScore"].asUInt();

							// IP address country
							result.countryCode = obj["data"]["countryCode"].asString();
							if (verbose) {
								result.countryName = obj["data"]["countryName"].asString();
							}

							// Report count for specified maxAgeInDays
							result.totalReports = obj["data"]["totalReports"].asUInt();

							// Last activity from this IP address
							if (obj["data"]["lastReportedAt"].asString().length() > 0) {
								if (strptime(obj["data"]["lastReportedAt"].asString().c_str(), this->config->abuseipdbDatetimeFormat.c_str(), &t) != 0) {
									timestamp = timegm(&t);
									result.lastReportedAt = (unsigned long long int)timestamp;
								} else {
									this->isError = true;
									this->log->error("Failed to parse date and time in AbuseIPDB API response!");
									result.lastReportedAt = 0;
								}
							}

							// Additional details with verbose flag
							if (verbose) {
								AbuseIPDBCheckResultReport report;
								for (i = 0; i < obj["data"]["reports"].size(); ++i) {
									// Date&time of report
									if (strptime(obj["data"]["reports"][i]["reportedAt"].asString().c_str(), this->config->abuseipdbDatetimeFormat.c_str(), &t) != 0) {
										timestamp = timegm(&t);
										report.reportedAt = (unsigned long long int)timestamp;
									} else {
										this->isError = true;
										this->log->error("Failed to parse date and time in AbuseIPDB API response!");
										report.reportedAt = 0;
									}

									// Comment
									report.comment = obj["data"]["reports"][i]["comment"].asString();

									// Categories
									report.categories.clear();
									for (j = 0; j < obj["data"]["reports"][i]["categories"].size(); j++) {
										report.categories.insert(report.categories.end(), obj["data"]["reports"][i]["categories"][j].asUInt());
									}

									// User identifier of reporter
									report.reporterId = obj["data"]["reports"][i]["reporterId"].asUInt();

									// Reporter country
									report.reporterCountryCode = obj["data"]["reports"][i]["reporterCountryCode"].asString();
									report.reporterCountryName = obj["data"]["reports"][i]["reporterCountryName"].asString();

									// Append to result
									result.reports.insert(result.reports.end(), report);
								}
							}
						}
					} else {
						this->isError = true;
						this->log->error("After calling AbuseIPDB API check service, failed to parse AbuseIPDB response! " + reader.getFormattedErrorMessages());
					}
				}
			}

			// cURL cleanup
			curl_easy_cleanup(this->curl);
		}

		// Memory cleanup
		free(chunk.memory);
	}

	return result;
}

bool AbuseIPDB::reportAddress(std::string address, std::string comment, std::vector<unsigned int> &categories)
{
	this->isError = false;

	if (categories.size() == 0) {
		this->isError = true;
		this->log->error("Address " + address + " not reported! Must provide at least one AbuseIPDB category to report!");
		return false;
	}

	// API key is mandatory
	if (this->config->abuseipdbKey.size() == 0) {
		this->isError = true;
		this->log->error("Cannot call AbuseIPDB API, API key is not provided!");
		return false;
	}

	// Check if limit has been reached
	std::time_t currentRawTime;
	std::time(&currentRawTime);
	unsigned long long int currentTime = (unsigned long long int)currentRawTime;
	if (currentTime < this->nextReportTimestamp) {
		this->log->debug("Not calling AbuseIPDB until " + std::to_string(this->nextReportTimestamp));
		return false;
	}

	if (this->isError == false) {
		// Mask part of comment
		if (this->config->abuseipdbReportMask) {
			std::size_t pos;
			// Mask all IP address and hostname occurrences
			for (auto it = this->stringsToMask.begin(); it != this->stringsToMask.end(); ++it) {
				pos = comment.find(*it);
				while (pos != std::string::npos) {
					comment = comment.replace(pos, (*it).length(), std::string((*it).length(), '*'));
					pos = comment.find(*it, pos);
				}
			}
		}

		// Init some memory where JSON response will be stored
		CurlData curlRespData;
		curlRespData.memory = (char*)malloc(1); // Will be extended with realloc later
		curlRespData.size = 0; // No data yet
		CurlData curlRespHeaders;
		curlRespHeaders.memory = (char*)malloc(1); // Will be extended with realloc later
		curlRespHeaders.size = 0; // No data yet
		CURLcode res;// cURL response code
		struct curl_slist *headers=NULL;// Init to NULL is important

		// Prepare URL, header and request parameters
		std::string url = this->config->abuseipdbURL;
		headers = curl_slist_append(headers, "Accept: application/json");
		headers = curl_slist_append(headers, ("Key: " + this->config->abuseipdbKey).c_str());
		url += "/api/v2/report";
		std::string requestParams = "categories=";
		std::vector<unsigned int>::iterator cit;
		bool firstIteration = true;
		for (cit = categories.begin(); cit != categories.end(); ++cit) {
			if (firstIteration) {
				requestParams += std::to_string(*cit);
				firstIteration = false;
			} else {
				requestParams += "," + std::to_string(*cit);
			}
		}
		requestParams += "&comment=" + std::string(curl_easy_escape(this->curl, comment.c_str(), comment.size()));
		requestParams += "&ip=" + address;

		// Init curl
		this->curl = curl_easy_init();

		if (this->curl) {
			// Set header
			curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, headers);

			// Store results using callback function
			curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveCurlDataCallback);

			// Store results into CurlData
			curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&curlRespData);

			// Store resulting headers using callback function
			curl_easy_setopt(this->curl, CURLOPT_HEADERFUNCTION, AbuseIPDB::SaveCurlDataCallback);

			// Store resulting headers into CurlData
			curl_easy_setopt(this->curl, CURLOPT_HEADERDATA, (void *)&curlRespHeaders);

			// User agent
			curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
			std::string userAgent = "Hostblock/";
			userAgent += kHostblockVersion;
			userAgent += " libcurl/";
			userAgent += versionData->version;
			curl_easy_setopt(this->curl, CURLOPT_USERAGENT, userAgent.c_str());

			// URL
			curl_easy_setopt(this->curl, CURLOPT_URL, url.c_str());

			// POST data
			curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, requestParams.c_str());

			// HTTP/HTTPs call
			this->log->debug("Calling " + url);
			this->log->debug("Data: " + requestParams);
			res = curl_easy_perform(curl);

			if (res != CURLE_OK) {
				this->isError = true;
				this->log->error("Failed to call AbuseIPDB API address report service! curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
			} else {
				// Get HTTP status code
				long httpCode;
				curl_easy_getinfo(this->curl, CURLINFO_RESPONSE_CODE, &httpCode);
				this->log->debug("Response received! HTTP status code: " + std::to_string(httpCode));
				this->log->debug("Received data size: " + std::to_string(curlRespData.size));

				std::string response = "";
				bool jsonParsed = false;
				Json::Reader reader;
				Json::Value obj;
				unsigned int i;
				if (curlRespData.size > 0) {
					// Convert response to string for libjson
					for (i = 0; i < curlRespData.size; ++i) {
						response += curlRespData.memory[i];
					}

					// Try parsing response as JSON
					jsonParsed = reader.parse(response, obj);
				}

				if (httpCode != 200) {
					this->isError = true;
					this->log->error("Failed to call AbuseIPDB API address report service! HTTP status code: " + std::to_string(httpCode));
					if (jsonParsed && obj.size() > 0 && obj.isMember("errors")) {
						this->isError = true;
						for (i = 0; i < obj["errors"].size(); ++i) {
							this->log->error(obj["errors"][i]["detail"].asString());
						}
					}

					// Check if limit has been reached
					if (httpCode == 429) {
						// Parse response headers
						std::string respHeadersRaw = "";
						if (curlRespHeaders.size > 0) {
							for (i = 0; i < curlRespHeaders.size; ++i) {
								respHeadersRaw += curlRespHeaders.memory[i];
							}
						}
						std::map<std::string, std::string> respHeaders = parseHeaders(respHeadersRaw);

						// Check if retry-after is specified to adjust when is the soonest we should send next report
						for (const auto & it : respHeaders) {
							if (hb::Util::toLower(it.first) == "retry-after") {
								this->nextReportTimestamp = currentTime + std::strtoull(it.second.c_str(), NULL, 10);
								this->log->warning("Reporting to AbuseIPDB disabled until: " + Util::formatDateTime((const time_t)this->nextReportTimestamp, this->config->abuseipdbDatetimeFormat.c_str()));
								break;
							}
						}
					}

				} else {
					if (jsonParsed) {
						if (obj.size() > 0) {
							if (obj.isMember("data")) {
								curl_easy_cleanup(this->curl);
								free(curlRespData.memory);
								this->nextReportTimestamp = currentTime;
								return true;
							} else if (obj.isMember("errors")) {
								this->isError = true;
								this->log->error("AbuseIPDB report service returned error(s)!");
								for (i = 0; i < obj["errors"].size(); ++i) {
									this->log->error(obj["errors"][i]["detail"].asString());
								}
							} else {
								this->isError = true;
								this->log->error("After calling AbuseIPDB API report servcie, failed to parse AbuseIPDB response!");
							}
						} else {
							// Did not get any JSON response, assume failure
							this->isError = true;
							this->log->error("No response from AbuseIPDB API report service!");
						}
					} else {
						this->isError = true;
						this->log->error("After calling AbuseIPDB API report service, failed to parse AbuseIPDB response! " + reader.getFormattedErrorMessages());
					}
				}
			}

			// cURL cleanup
			curl_easy_cleanup(this->curl);
		}

		// Memory cleanup
		free(curlRespData.memory);
	}

	return false;
}

bool AbuseIPDB::getBlacklist(unsigned int confidenceMinimum, unsigned long long int* generatedAt, std::map<std::string, hb::AbuseIPDBBlacklistedAddressType>* blacklist)
{
	this->isError = false;

	// API key is mandatory
	if (this->config->abuseipdbKey.size() == 0) {
		this->isError = true;
		this->log->error("Cannot call AbuseIPDB API, API key is not provided!");
	}

	if (this->isError == false) {
		// Init some memory where JSON response will be stored
		CurlData chunk;
		chunk.memory = (char*)malloc(1); // Will be extended with realloc later
		chunk.size = 0; // No data yet
		CURLcode res;// cURL response code
		struct curl_slist *headers=NULL;// Init to NULL is important

		// Prepare URL, header and request parameters
		std::string url = this->config->abuseipdbURL;
		headers = curl_slist_append(headers, "Accept: application/json");
		headers = curl_slist_append(headers, ("Key: " + this->config->abuseipdbKey).c_str());
		url += "/api/v2/blacklist";
		std::string requestParams = "confidenceMinimum=" + std::to_string(confidenceMinimum);

		// Init curl
		this->curl = curl_easy_init();

		if (this->curl) {
			// Set header
			curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, headers);

			// Store results using callback function
			curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveCurlDataCallback);

			// Store results into CurlData
			curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&chunk);

			// User agent
			curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
			std::string userAgent = "Hostblock/";
			userAgent += kHostblockVersion;
			userAgent += " libcurl/";
			userAgent += versionData->version;
			curl_easy_setopt(this->curl, CURLOPT_USERAGENT, userAgent.c_str());

			// URL and request parameters
			curl_easy_setopt(this->curl, CURLOPT_URL, (url + "?" + requestParams).c_str());

			// HTTP/HTTPs call
			this->log->debug("Calling " + url);
			this->log->debug("Data: " + requestParams);
			clock_t cpuStart = clock(), cpuEnd = cpuStart;
			auto wallStart = std::chrono::steady_clock::now(), wallEnd = wallStart;
			res = curl_easy_perform(this->curl);
			cpuEnd = clock();
			wallEnd = std::chrono::steady_clock::now();
			this->log->debug("AbuseIPDB API response in " + std::to_string((double)(cpuEnd - cpuStart) / CLOCKS_PER_SEC) + " CPU sec (" + std::to_string((std::chrono::duration<double>(wallEnd - wallStart)).count()) + " sec)");

			if (res != CURLE_OK) {
				this->isError = true;
				this->log->error("Failed to call AbuseIPDB API blacklist service! curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
			} else {
				// Get HTTP status code
				long httpCode;
				curl_easy_getinfo(this->curl, CURLINFO_RESPONSE_CODE, &httpCode);
				this->log->debug("Response received! HTTP status code: " + std::to_string(httpCode));

				// Must have http status code 200
				if (httpCode != 200) {
					this->isError = true;
					this->log->error("Failed to call AbuseIPDB API blacklist service! HTTP status code: " + std::to_string(httpCode));
				} else {
					this->log->debug("Received data size: " + std::to_string(chunk.size));

					// Convert to string for libjson
					unsigned int i;
					std::string response = "";
					for (i = 0; i < chunk.size; ++i) {
						response += chunk.memory[i];
					}
					// std::cout << "Response: " << response << std::endl;

					// Parse JSON
					Json::Reader reader;
					Json::Value obj;
					std::tm t = {};
					std::time_t timestamp;
					std::time(&timestamp);
					std::string address;
					if (reader.parse(response, obj)) {
						if (obj.size() > 0) {
							// Blacklist generation time
							if (obj["meta"]["generatedAt"].asString().length() > 0) {
								std::string generatedAtStr = obj["meta"]["generatedAt"].asString();
								this->log->debug("Blacklist generation time (raw): " + generatedAtStr);
								if (strptime(generatedAtStr.c_str(), this->config->abuseipdbDatetimeFormat.c_str(), &t) != 0) {
									timestamp = timegm(&t);
									// Workaround for AbuseIPDB provided timezone in format +01:00
									if ((generatedAtStr.substr(generatedAtStr.length() - 6, 1) == "+" || generatedAtStr.substr(generatedAtStr.length() - 6, 1) == "-") && generatedAtStr.substr(generatedAtStr.length() - 3, 1) == ":") {
										unsigned int offsetH = std::strtoul(generatedAtStr.substr(generatedAtStr.length() - 5, 2).c_str(), NULL, 10);
										unsigned int offsetM = std::strtoul(generatedAtStr.substr(generatedAtStr.length() - 2, 2).c_str(), NULL, 10);
										if (generatedAtStr.substr(generatedAtStr.length() - 6, 1) == "+") {
											timestamp -= (60 * 60 * offsetH) + (60 * offsetM);
										} else if (generatedAtStr.substr(generatedAtStr.length() - 6, 1) == "-") {
											timestamp += (60 * 60 * offsetH) + (60 * offsetM);
										}
									}
									*generatedAt = (unsigned long long int)timestamp;
								} else {
									this->isError = true;
									this->log->error("Failed to parse date and time in AbuseIPDB API response!");
									generatedAt = 0;
								}
							}

							// Clear blacklist
							blacklist->clear();

							this->log->debug("Data array size: " + std::to_string(obj["data"].size()));

							// Fill blacklist with new data
							for (i = 0; i < obj["data"].size(); ++i) {
								AbuseIPDBBlacklistedAddressType data;

								// IP address
								address = obj["data"][i]["ipAddress"].asString();

								// Total reports
								data.totalReports = obj["data"][i]["totalReports"].asUInt();

								// Confidence score
								data.abuseConfidenceScore = std::strtoul(obj["data"][i]["abuseConfidenceScore"].asString().c_str(), NULL, 10);

								// Append to blacklist
								blacklist->insert(std::pair<std::string,AbuseIPDBBlacklistedAddressType>(address, data));
							}
						}
					} else {
						this->isError = true;
						this->log->error("After calling AbuseIPDB API blacklist service, failed to parse AbuseIPDB response! " + reader.getFormattedErrorMessages());
					}
				}
			}

			// cURL cleanup
			curl_easy_cleanup(this->curl);
		}

		// Memory cleanup
		free(chunk.memory);
	}

	if (this->isError) {
		return false;
	} else {
		return true;
	}
}

size_t AbuseIPDB::SaveCurlDataCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realSize = size * nmemb;
	struct CurlData *mem = (struct CurlData *) userp;

	mem->memory = (char*)std::realloc(mem->memory, mem->size + realSize + 1);
	if (mem->memory == NULL) {
		std::cerr << "Not enough memory (realloc returned NULL)!" << std::endl;
		return 0;
	}

	std::memcpy(&(mem->memory[mem->size]), contents, realSize);
	mem->size += realSize;
	mem->memory[mem->size] = 0;

	return realSize;
}
