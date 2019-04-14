/*
 * Class to work with data file.
 */

#ifndef HBDATA_H
#define HBDATA_H

// Map
#include <map>
// String
#include <string>
// Logger
#include "logger.h"
// Config
#include "config.h"
// Iptables
#include "iptables.h"
// Util
#include "util.h"

namespace hb{

class Data{
	private:

		static bool sortByActivityCount(const hb::SuspiciosAddressStatType& la, const hb::SuspiciosAddressStatType& ra);

		static bool sortByLastActivity(const hb::SuspiciosAddressStatType& la, const hb::SuspiciosAddressStatType& ra);

		static std::string centerString(std::string str, unsigned int len);

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
		 * Data about suspicious, whitelisted and blacklisted addresses
		 */
		std::map<std::string, hb::SuspiciosAddressType> suspiciousAddresses;

		/*
		 * Timestamp of last syncrhonization with AbuseIPDB blacklist
		 */
		unsigned long long int abuseIPDBSyncTime = 0;

		/*
		 * Timestamp of AbuseIPDB blacklist generation (received from AbuseIPDB)
		 */
		unsigned long long int abuseIPDBBlacklistGenTime = 0;

		/*
		 * Data about AbuseIPDB blacklisted addresses
		 */
		std::map<std::string, hb::AbuseIPDBBlacklistedAddressType> abuseIPDBBlacklist;

		/*
		 * Constructor
		 */
		Data(hb::Logger* log, hb::Config* config, hb::Iptables* iptables);

		/*
		 * Read data file and store results in this->suspiciousAddresses
		 */
		bool loadData();

		/*
		 * Save this->suspiciousAddresses to data file, will replace if file already exists
		 * Warhing, this rewrites whole file, should not be used for single record updates
		 * Instead there are separate methods for single record updates that replace only single line in file
		 * This method is intended only to keep data file cleaner, to use this on normal shutdown
		 */
		bool saveData();

		/*
		 * Compare data with iptables rules
		 */
		bool checkIptables();

		/*
		 * Add new record to datafile based on this->suspiciousAddresses
		 */
		bool addAddress(std::string address);

		/*
		 * Update record in datafile based on this->suspiciousAddresses
		 */
		bool updateAddress(std::string address);

		/*
		 * Mark record for removal in datafile
		 */
		bool removeAddress(std::string address);

		/*
		 * Add new log file bookmark record to datafile
		 */
		bool addFile(std::string filePath);

		/*
		 * Update log file bookmark record in datafile
		 */
		bool updateFile(std::string filePath);

		/*
		 * Mark log file bookmark record for removal in datafile
		 */
		bool removeFile(std::string filePath);

		/*
		 * Add new record to datafile based on this->abuseIPDBBlacklist
		 */
		bool addAbuseIPDBAddress(std::string address);

		/*
		 * Update record in datafile based on this->abuseIPDBBlacklist
		 */
		bool updateAbuseIPDBAddress(std::string address);

		/*
		 * Mark AbuseIPDB blacklist record for removal in datafile
		 */
		bool removeAbuseIPDBAddress(std::string address);

		/*
		 * Add/remove iptables rule based on score and blacklist
		 */
		bool updateIptables(std::string address);

		/*
		 * Save suspicious activity (add new or update existing) and create/remove iptables rule if needed
		 */
		void saveActivity(std::string address, unsigned int activityScore, unsigned int activityCount, unsigned int refusedCount);

		/*
		 * Save AbuseIPDB blacklist record (add new or update existing) and create/remove iptables rule if needed
		 */
		void saveAbuseIPDBRecord(std::string address, unsigned int totalReports, unsigned int abuseConfidenceScore);

		/*
		 * Print (stdout) some statistics about data
		 */
		void printStats();

		/*
		 * Print (stdout) list of all blocked addresses
		 */
		void printBlocked(bool count = false, bool time = false, bool all = false);

};

}

#endif
