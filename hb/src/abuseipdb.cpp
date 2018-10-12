/*
 * Class to work with AbuseIPDB API
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

std::vector<ReportFromAbuseIPDB> AbuseIPDB::checkAddress(std::string address, bool verbose)
{
	// No error at start
	this->isError = false;

	// API key is mandatory
	if (this->abuseipdbKey.size() == 0) {
		this->isError = true;
		this->log->error("Cannot call AbuseIPDB API, API key is not provided!");
	}

	// AbuseIPDBCheckResult result;// Result
	std::vector<ReportFromAbuseIPDB> result;

	// Init some memory where JSON response will be stored
	AbuseIPDBJSONData chunk;
	chunk.memory = (char*)malloc(1); // Will be extended with realloc later
	chunk.size = 0; // No data yet
	CURLcode res;// cURL response code

	// Prepare URL and POST data
	std::string url = this->abuseipdbURL + "/check/" + address + "/json";
	std::string postFields = "key=" + this->abuseipdbKey;
	postFields += "&days=7";
	if (verbose) {
		postFields += "&verbose";
	}

	// Init curl
	this->curl = curl_easy_init();

	// Store results using callback function
	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveJSONResultCallback);

	// Store results into AbuseIPDBJSONData
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&chunk);

	// User agent
	curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
	std::string userAgent = "Hostblock/1.0.1 libcurl/";
	userAgent += versionData->version;
	curl_easy_setopt(this->curl, CURLOPT_USERAGENT, userAgent.c_str());

	if (this->curl) {
		// URL
		curl_easy_setopt(this->curl, CURLOPT_URL, url.c_str());

		// POST data
		curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, postFields.c_str());

		// HTTP/HTTPs call
		this->log->debug("Calling " + url);
		this->log->debug("POST data: " + postFields);
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

				// AbuseIPDB doesn't have any reports about this address, return empty result
				if (response == "[]") {
					curl_easy_cleanup(this->curl);
					free(chunk.memory);
					return result;
				}

				// Parse JSON and store into hb::AbuseIPDBCheckResult
				Json::Reader reader;
				Json::Value obj;
				std::tm t = {};
				std::time_t timestamp;
				std::time(&timestamp);
				if (reader.parse(response, obj)) {
					// std::cout << "count: " << obj.size() << std::endl;
					if (obj.size() > 0) {
						for (i = 0; i < obj.size(); ++i) {
							ReportFromAbuseIPDB report;

							// IP address
							report.ip = obj[i]["ip"].asString();

							// Categories
							for (j = 0; j < obj[i]["category"].size(); j++) {
								report.categories.insert(report.categories.end(), obj[i]["category"][j].asUInt());
							}

							// Date and time of report
							// std::istringstream ss(obj[i]["created"].asString());
							// ss >> std::get_time(&t, this->abuseipdbDatetimeFormat.c_str());
							// if (ss.fail()) {
							// 	this->isError = true;
							// 	this->log->error("Failed to parse date and time in AbuseIPDB API response!");
							// 	report.created = 0;
							// } else {
							// 	timestamp = timegm(&t);
							// 	report.created = (unsigned long long int)timestamp;
							// }
							if (strptime(obj[i]["created"].asString().c_str(), this->abuseipdbDatetimeFormat.c_str(), &t) != 0) {
								timestamp = timegm(&t);
								report.created = (unsigned long long int)timestamp;
							} else {
								this->isError = true;
								this->log->error("Failed to parse date and time in AbuseIPDB API response!");
								report.created = 0;
							}

							// IP address country
							report.country = obj[i]["country"].asString();

							// IP address country ISO code
							report.isoCode = obj[i]["isoCode"].asString();

							// Whitelist flag
							report.isWhitelisted = false;
							if (obj[i]["isWhitelisted"] == "true") {
								report.isWhitelisted = true;
							}

							if (obj[i].isMember("abuseConfidenceScore")) {
								report.score =  obj[i]["abuseConfidenceScore"].asUInt();
							} else {
								report.score = 0;
							}

							// Comment
							if (obj[i].isMember("comment")) {
								report.comment = obj[i]["comment"].asString();
							} else {
								report.comment = "";
							}

							// User who reported
							if (obj[i].isMember("userId")) {
								report.userId = obj[i]["userId"].asUInt();
							} else {
								report.userId = 0;
							}
							result.insert(result.end(), report);
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

	// Prepare URL and POST data
	std::string url = this->abuseipdbURL + "/report/json";
	std::string postFields = "key=" + this->abuseipdbKey;
	postFields += "&category=";
	std::vector<unsigned int>::iterator cit;
	bool firstIteration = true;
	for (cit = categories.begin(); cit != categories.end(); ++cit) {
		if (firstIteration) {
			postFields += std::to_string(*cit);
			firstIteration = false;
		} else {
			postFields += "," + std::to_string(*cit);
		}
	}
	postFields += "&comment=" + std::string(curl_easy_escape(this->curl, comment.c_str(), comment.size()));
	postFields += "&ip=" + address;

	// Init curl
	this->curl = curl_easy_init();

	// Store results using callback function
	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveJSONResultCallback);

	// Store results into AbuseIPDBJSONData
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&chunk);

	// User agent
	curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
	std::string userAgent = "Hostblock/1.0.1 libcurl/";
	userAgent += versionData->version;
	curl_easy_setopt(this->curl, CURLOPT_USERAGENT, userAgent.c_str());

	if (this->curl) {
		// URL
		curl_easy_setopt(this->curl, CURLOPT_URL, url.c_str());

		// POST data
		curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, postFields.c_str());

		// HTTP/HTTPs call
		this->log->debug("Calling " + url);
		this->log->debug("POST data: " + postFields);
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
						// Check response, whether in JSON we got success == true
						if (obj["success"] == true) {
							curl_easy_cleanup(this->curl);
							free(chunk.memory);
							return true;
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
