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
// Vector
#include <vector>
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
bool Iptables::newChain(std::string chain, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "ip";
	if (version == 6) cmd += "6";
	cmd += "tables -N " + chain;
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
 * Append rule to the end of the chain
 */
bool Iptables::append(std::string chain, std::string rule, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "ip";
	if (version == 6) cmd += "6";
	cmd += "tables -A " + chain + " " + rule;
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
 * Append multiple rules to the end of the chain
 */
bool Iptables::append(std::string chain, std::vector<std::string>* rules, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	int response = 0;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	std::string cmd;
	for (std::vector<std::string>::iterator it = rules->begin(); it != rules->end(); ++it) {
		cmd = "ip";
		if (version == 6) cmd += "6";
		cmd += "tables -A " + chain + " " + *it;
		response = std::system(cmd.c_str());
		if (response != 0) {
			throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
		}
	}

	return true;
}

/*
 * Insert rule to the chain at specified position
 */
bool Iptables::insert(std::string chain, std::string rule, int version, int pos)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "ip";
	if (version == 6) cmd += "6";
	cmd += "tables -I " + chain + " " + std::to_string(pos) + " " + rule;
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
 * Insert multiple rules at specified position in chain
 */
bool Iptables::insert(std::string chain, std::vector<std::string>* rules, int version, int pos)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	int response = 0;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	std::string cmd;
	for (std::vector<std::string>::iterator it = rules->begin(); it != rules->end(); ++it) {
		cmd = "ip";
		if (version == 6) cmd += "6";
		cmd += "tables -I " + chain + " " + std::to_string(pos) + " " + *it;
		response = std::system(cmd.c_str());
		if (response != 0) {
			throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
		}
	}

	return true;
}

/*
 * Delete rule from chain
 */
bool Iptables::remove(std::string chain, std::string rule, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "ip";
	if (version == 6) cmd += "6";
	cmd += "tables -D " + chain + " " + rule;
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
 * Delete rules from chain
 */
bool Iptables::remove(std::string chain, std::vector<std::string>* rules, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	int response = 0;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	std::string cmd;
	for (std::vector<std::string>::iterator it = rules->begin(); it != rules->end(); ++it) {
		cmd = "ip";
		if (version == 6) cmd += "6";
		cmd += "tables -D " + chain + " " + *it;
		response = std::system(cmd.c_str());
		if (response != 0) {
			throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
		}
	}

	return true;
}

/*
 * List chain rules
 */
void Iptables::listRules(std::string chain, std::vector<std::string>& rules, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Command
	std::string cmd = "ip";
	if (version == 6) cmd += "6";
	cmd += "tables --list-rules " + chain;

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
		rules.push_back(line);
	}
	return;
}

/*
 * Exec iptables any command with custom options
 */
int Iptables::command(std::string options, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	// Prepare command
	std::string cmd = "ip";
	if (version == 6) cmd += "6";
	cmd += "tables " + options;
	if (!std::system(NULL)) {
		throw std::runtime_error("Command processor not available.");
	}

	// Exec command
	return std::system(cmd.c_str());
}

/*
 * Exec iptables any command with custom options and return stdout in map each line as entry in map
 */
std::map<unsigned int, std::string> Iptables::custom(std::string options, int version)
{
	// Need root access to work with iptables
	if (cunistd::getuid() != 0) {
		throw std::runtime_error("Error, root access required to work with iptables!");
	}

	std::map<unsigned int, std::string> stdoutResult;
	unsigned int stdoutResultInd = 0;
	stdoutResult.clear();
	std::string cmd = "ip";
	if (version == 6) cmd += "6";
	cmd += "tables " + options;

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
