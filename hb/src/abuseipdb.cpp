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
// cURL
#include <curl/curl.h>
// libjsoncpp1
#include <jsoncpp/json/json.h>
// Config
#include "config.h"
// Header
#include "abuseipdb.h"

// Hostblock namespace
using namespace hb;

AbuseIPDB::AbuseIPDB(hb::Logger* log, hb::Config* config)
: log(log), config(config)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	this->curl = curl_easy_init();
}

AbuseIPDB::~AbuseIPDB()
{
	curl_global_cleanup();
}

std::vector<AbuseIPDBReport> AbuseIPDB::checkAddress(std::string address, bool verbose)
{
	// AbuseIPDBCheckResult result;// Result
	std::vector<AbuseIPDBReport> result;

	// Init some memory where JSON response will be stored
	JSONData chunk;
	chunk.memory = (char*)malloc(1); // Will be extended with realloc later
	chunk.size = 0; // No data yet
	CURLcode res;// cURL response code

	// Prepare URL and POST data
	std::string url = this->config->abuseipdbURL + "/check/" + address + "/json";
	std::string postFields = "key=" + this->config->abuseipdbKey;
	postFields += "&days=7";
	if (verbose) {
		postFields += "&verbose";
	}

	// Store results using callback function
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AbuseIPDB::SaveJSONResultCallback);

	// Store results into JSONData
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	// User agent
	curl_version_info_data *versionData = curl_version_info(CURLVERSION_NOW);
	std::string userAgent = "Hostblock/1.0.1 libcurl/";
	userAgent += versionData->version;
	curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent.c_str());

	if (curl) {
		// URL
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		// POST data
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

		// HTTP/HTTPs call
		this->log->debug("Calling " + url);
		this->log->debug("POST data: " + postFields);
		res = curl_easy_perform(curl);

		// Get HTTP status code
		long httpCode;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
		this->log->debug("Response received! HTTP status code: " + std::to_string(httpCode));

		if (res != CURLE_OK) {
			this->log->error("Failed to call AbuseIPDB API address check service! curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
		} else {
			if (httpCode != 200) {
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
							hb::AbuseIPDBReport report;

							report.ip = obj[i]["ip"].asString();

							for (j = 0; j < obj[i]["category"].size(); j++) {
								report.categories.insert(report.categories.end(), obj[i]["category"][j].asUInt());
							}

							std::istringstream ss(obj[i]["created"].asString());
							ss >> std::get_time(&t, this->config->abuseipdbDatetimeFormat.c_str());
							if (ss.fail()) {
								this->log->error("Failed to parse date and time in AbuseIPDB API response!");
								report.created = 0;
							} else {
								timestamp = timegm(&t);
								report.created = (unsigned long long int)timestamp;
							}

							report.country = obj[i]["country"].asString();

							report.isoCode = obj[i]["isoCode"].asString();

							report.isWhitelisted = false;
							if (obj[i]["isWhitelisted"] == "true") {
								report.isWhitelisted = true;
							}

							if (obj[i].isMember("comment")) {
								report.comment = obj[i]["comment"].asString();
							} else {
								report.comment = "";
							}

							if (obj[i].isMember("userId")) {
								report.userId = obj[i]["userId"].asUInt();
							} else {
								report.userId = 0;
							}
							result.insert(result.end(), report);
						}
					} else {
						// AbuseIPDB doesn't have any reports about this address, return empty result
						return result;
					}
				} else {
					this->log->error("After calling AbuseIPDB API check servcie, failed to parse AbuseIPDB response! " + reader.getFormattedErrorMessages());
				}
			}
			// cURL cleanup
			curl_easy_cleanup(curl);
		}
	}

	// Memory cleanup
	free(chunk.memory);

	return result;
}

bool AbuseIPDB::reportAddress(std::string address, std::string comment, std::vector<int> categories, bool asynchronous)
{

	return false;
}

size_t AbuseIPDB::SaveJSONResultCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realSize = size * nmemb;
	struct JSONData *mem = (struct JSONData *) userp;

	mem->memory = (char*)realloc(mem->memory, mem->size + realSize + 1);
	if (mem->memory == NULL) {
		std::cerr << "Not enough memory (realloc returned NULL)!" << std::endl;
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realSize);
	mem->size += realSize;
	mem->memory[mem->size] = 0;

	return realSize;
}
