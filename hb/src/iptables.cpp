/*
 * Simple class to work with iptables
 * No API at the moment so using stdio, see:
 * http://www.netfilter.org/documentation/FAQ/netfilter-faq-4.html#ss4.5
 * Shoud rewrite once/if some API is available.
 */

// Standard input/output stream library (cin, cout, cerr, clog, etc)
#include <iostream>
// Standard string library
#include <string>
// String stream library
#include <sstream>
// Standard map library
#include <map>
// Exceptions
#include <exception>
// Standard input/output C library (fopen, fgets, fputs, fclose, etc)
#include <cstdio>
// POSIX (getuid, sleep, usleep, rmdir, chroot, chdir, etc)
namespace cunistd{
	#include <unistd.h>
}
// Header
#include "iptables.h"

// Hostblock namespace
using namespace hb;

Iptables::Iptables()
{

}

/*
 * Create new chain
 */
bool Iptables::newChain(std::string chain)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "iptables -N " + chain;
	int response = 0;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	// Exec command
	response = std::system(cmd.c_str());

	// Check response
	if (response == 0) {
		return true;
	} else {
		throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
	}
}

/*
 * Append rule to chain
 */
bool Iptables::append(std::string chain, std::string rule)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "iptables -A " + chain + " " + rule;
	int response = 0;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	// Exec command
	response = std::system(cmd.c_str());

	// Check response
	if (response == 0) {
		return true;
	} else {
		throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
	}
}

/*
 * Delete rule from chain
 */
bool Iptables::remove(std::string chain, std::string rule)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "iptables -D " + chain + " " + rule;
	int response = 0;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	// Exec command
	response = std::system(cmd.c_str());

	// Check response
	if (response == 0) {
		return true;
	} else {
		throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
	}
}

/*
 * List chain rules
 */
std::map<unsigned int, std::string> Iptables::listRules(std::string chain)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	std::map<unsigned int, std::string> rules;
	unsigned int ruleInd = 0;
	rules.clear();
	std::string cmd = "iptables --list-rules " + chain;

	// Open pipe stream
	FILE* pipe = popen(cmd.c_str(), "r");
	if (!pipe) {
		throw std::runtime_error("Unable to open pipe to iptables for rule listing.");
	}
	char buffer[128];
	std::string result = "";

	// Read pipe stream
	while (!feof(pipe)) {
		if(fgets(buffer, 128, pipe) != NULL) result += buffer;
	}

	// Close stream
	pclose(pipe);

	// Read result line by line
	std::istringstream iss(result);
	std::string line;
	for (line = ""; std::getline(iss, line);) {
		rules.insert(std::pair<unsigned int, std::string>(ruleInd, line));
		++ruleInd;
	}
	return rules;
}

/*
 * Exec iptables any command with custom options
 */
bool Iptables::command(std::string options)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "iptables " + options;
	int response = 0;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	// Exec command
	response = std::system(cmd.c_str());

	// Check response
	if (response == 0) {
		return true;
	} else {
		throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
	}
}

/*
 * Exec iptables any command with custom options and return stdout in map each line as entry in map
 */
std::map<unsigned int, std::string> Iptables::custom(std::string options)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	std::map<unsigned int, std::string> stdoutResult;
	unsigned int stdoutResultInd = 0;
	stdoutResult.clear();
	std::string cmd = "iptables " + options;

	// Open pipe stream
	FILE* pipe = popen(cmd.c_str(), "r");
	if (!pipe) {
		throw std::runtime_error("Unable to open pipe to iptables for rule listing.");
	}
	char buffer[128];
	std::string result = "";

	// Read pipe stream
	while (!feof(pipe)) {
		if(fgets(buffer, 128, pipe) != NULL) result += buffer;
	}

	// Close stream
	pclose(pipe);

	// Read result line by line
	std::istringstream iss(result);
	std::string line;
	for (line = ""; std::getline(iss, line);) {
		stdoutResult.insert(std::pair<unsigned int, std::string>(stdoutResultInd, line));
		++stdoutResultInd;
	}
	return stdoutResult;
}
