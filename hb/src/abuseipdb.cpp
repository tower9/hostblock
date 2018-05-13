/*
 * Class to work with AbuseIPDB API
 */
// Vector
#include <vector>
// Standard string library
#include <string>
// cURL
#include <curl/curl.h>
// Header
#include "abuseipdb.h"

// Hostblock namespace
using namespace hb;

AbuseIPDB::AbuseIPDB()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	this->curl = curl_easy_init();
}

AbuseIPDBCheckResult AbuseIPDB::checkAddress(std::string address)
{
	AbuseIPDBCheckResult result;

	return result;
}

bool AbuseIPDB::reportAddress(std::string address, std::string comment, std::vector<int> categories, bool asynchronous)
{

	return false;
}
