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
// (get_time, put_time)
#include <iomanip>
// memcpy
#include <cstring>
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

AbuseIPDB::AbuseIPDB(hb::Logger* log)
: log(log)
{
	this->init();
}
AbuseIPDB::AbuseIPDB(hb::Logger* log, std::string abuseipdbURL)
: log(log), abuseipdbURL(abuseipdbURL)
{
	this->init();
}
AbuseIPDB::AbuseIPDB(hb::Logger* log, std::string abuseipdbURL, std::string abuseipdbKey)
: log(log), abuseipdbURL(abuseipdbURL), abuseipdbKey(abuseipdbKey)
{
	this->init();
}
AbuseIPDB::AbuseIPDB(hb::Logger* log, std::string abuseipdbURL, std::string abuseipdbKey, std::string abuseipdbDatetimeFormat)
: log(log), abuseipdbURL(abuseipdbURL), abuseipdbKey(abuseipdbKey), abuseipdbDatetimeFormat(abuseipdbDatetimeFormat)
{
	this->init();
}

void AbuseIPDB::init()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	this->curl = curl_easy_init();
}

AbuseIPDB::~AbuseIPDB()
{
	curl_global_cleanup();
}

AbuseIPDBCheckResult AbuseIPDB::checkAddress(std::string address, bool verbose)
{
	// No error at start
	this->isError = false;

	// API key is mandatory
	if (this->abuseipdbKey.size() == 0) {
		this->isError = true;
		this->log->error("Cannot call AbuseIPDB API, API key is not provided!");
	}

	AbuseIPDBCheckResult result;

	// Init some memory where JSON response will be stored
	AbuseIPDBJSONData chunk;
	chunk.memory = (char*)malloc(1); // Will be extended with realloc later
	chunk.size = 0; // No data yet
	CURLcode res;// cURL response code
	struct curl_slist *headers=NULL;// Init to NULL is important

	// Prepare URL, header and request parameters
	std::string url = this->abuseipdbURL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, ("Key: " + this->abuseipdbKey).c_str());
	url += "/api/v2/check";
	std::string requestParams = "ipAddress=" + address;
	requestParams += "&maxAgeInDays=7";
	if (verbose) {
		requestParams += "&verbose";
	}

	// Init curl
	this->curl = curl_easy_init();

	// Set header
	curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, headers);

	// Store results using callback function
	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveJSONResultCallback);

	// Store results into AbuseIPDBJSONData
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&chunk);

	// User agent
	curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
	std::string userAgent = "Hostblock/";
	userAgent += kHostblockVersion;
	userAgent += " libcurl/";
	userAgent += versionData->version;
	curl_easy_setopt(this->curl, CURLOPT_USERAGENT, userAgent.c_str());

	if (this->curl) {
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
							if (strptime(obj["data"]["lastReportedAt"].asString().c_str(), this->abuseipdbDatetimeFormat.c_str(), &t) != 0) {
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
								if (strptime(obj["data"]["reports"][i]["reportedAt"].asString().c_str(), this->abuseipdbDatetimeFormat.c_str(), &t) != 0) {
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
					this->log->error("After calling AbuseIPDB API check servcie, failed to parse AbuseIPDB response! " + reader.getFormattedErrorMessages());
				}
			}
			// cURL cleanup
			curl_easy_cleanup(this->curl);
		}
	}

	// Memory cleanup
	free(chunk.memory);

	return result;
}

bool AbuseIPDB::reportAddress(std::string address, std::string comment, std::vector<unsigned int> &categories)
{
	if (categories.size() == 0) {
		this->isError = true;
		this->log->error("Address " + address + " not reported! Must provide at least one AbuseIPDB category to report!");
		return false;
	}

	// API key is mandatory
	if (this->abuseipdbKey.size() == 0) {
		this->isError = true;
		this->log->error("Cannot call AbuseIPDB API, API key is not provided!");
	}

	// Init some memory where JSON response will be stored
	AbuseIPDBJSONData chunk;
	chunk.memory = (char*)malloc(1); // Will be extended with realloc later
	chunk.size = 0; // No data yet
	CURLcode res;// cURL response code
	struct curl_slist *headers=NULL;// Init to NULL is important

	// Prepare URL, header and request parameters
	std::string url = this->abuseipdbURL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, ("Key: " + this->abuseipdbKey).c_str());
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

	// Set header
	curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, headers);

	// Store results using callback function
	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveJSONResultCallback);

	// Store results into AbuseIPDBJSONData
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&chunk);

	// User agent
	curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
	std::string userAgent = "Hostblock/";
	userAgent += kHostblockVersion;
	userAgent += " libcurl/";
	userAgent += versionData->version;
	curl_easy_setopt(this->curl, CURLOPT_USERAGENT, userAgent.c_str());

	if (this->curl) {
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

			// Must have http status code 200
			if (httpCode != 200) {
				this->isError = true;
				this->log->error("Failed to call AbuseIPDB API address report service! HTTP status code: " + std::to_string(httpCode));
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
				if (reader.parse(response, obj)) {
					// std::cout << "count: " << obj.size() << std::endl;
					if (obj.size() > 0) {
						if (obj.isMember("data")) {
							curl_easy_cleanup(this->curl);
							free(chunk.memory);
							return true;
						} else if (obj.isMember("errors")) {
							this->isError = true;
							this->log->error("AbuseIPDB report service returned error(s)!");
							for (i = 0; i < obj["errors"].size(); ++i) {
								this->log->error(obj["errors"][i]["detail"].asString());
							}
							return false;
						} else {
							this->isError = true;
							this->log->error("After calling AbuseIPDB API report servcie, failed to parse AbuseIPDB response!");
						}
					} else {
						// Didn't get any JSON response, assume failure
						this->isError = true;
						this->log->error("No response from AbuseIPDB API report service!");
					}
				} else {
					this->isError = true;
					this->log->error("After calling AbuseIPDB API report servcie, failed to parse AbuseIPDB response! " + reader.getFormattedErrorMessages());
				}
			}
			// cURL cleanup
			curl_easy_cleanup(this->curl);
		}
	}

	// Memory cleanup
	free(chunk.memory);

	return false;
}

size_t AbuseIPDB::SaveJSONResultCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realSize = size * nmemb;
	struct AbuseIPDBJSONData *mem = (struct AbuseIPDBJSONData *) userp;

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
