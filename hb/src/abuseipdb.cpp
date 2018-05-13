/*
 * Class to work with AbuseIPDB API
 */
// Vector
#include <vector>
// Standard string library
#include <string>
// Header
#include "abuseipdb.h"

// Hostblock namespace
using namespace hb;

AbuseIPDB::AbuseIPDB()
{

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
