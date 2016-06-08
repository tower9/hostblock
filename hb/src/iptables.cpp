/* 
 * Simple class to work with iptables
 * No API at the moment so using stdio, see:
 * http://www.netfilter.org/documentation/FAQ/netfilter-faq-4.html#ss4.5
 * Shoud rewrite once/if some API is available.
 */

// Standard input/output stream library (cin, cout, cerr, clog, etc)
#include <iostream>
// Standard input/output library (fopen, fgets, fputs, fclose, etc)
#include <stdio.h>
// Standard string library
#include <string>
// String stream library
#include <sstream>
// Standard map library
#include <map>
// Exceptions
#include <exception>
// POSIX (getuid, sleep, usleep, rmdir, chroot, chdir, etc)
#include <unistd.h>
// Header
#include "iptables.h"

// Hostblock namespace
using namespace hb;

Iptables::Iptables()
{
	// Need root access to work with iptables
	if(getuid() != 0){
		throw std::runtime_error("Error, root access required to work with iptables!");
	}
}

/*
 * Append rule to chain
 */
bool Iptables::append(std::string chain, std::string rule)
{
	// Prepare command
	std::string cmd = "iptables -A "+chain+" "+rule;
	int response = 0;
	if(!system(NULL)){
		throw std::runtime_error("Command processor not available.");
	}

	// Exec command
	response = system(cmd.c_str());

	// Check response
	if(response == 0){
		return true;
	}
	else{
		throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
	}
}

/*
 * Delete rule from chain
 */
bool Iptables::remove(std::string chain, std::string rule)
{
	// Prepare command
	std::string cmd = "iptables -D "+chain+" "+rule;
	int response = 0;
	if(!system(NULL)){
		throw std::runtime_error("Command processor not available.");
	}

	// Exec command
	response = system(cmd.c_str());

	// Check response
	if(response == 0){
		return true;
	}
	else{
		throw std::runtime_error("Failed to execute iptables, returned code: " + std::to_string(response));
	}
}

/*
 * List chain rules
 */
std::map<unsigned int, std::string> Iptables::listRules(std::string chain)
{
	std::map<unsigned int, std::string> rules;
	unsigned int ruleInd = 0;
	rules.clear();
	std::string cmd = "iptables --list-rules "+chain;

	// Open pipe stream
	FILE* pipe = popen(cmd.c_str(), "r");
	if(!pipe){
		throw std::runtime_error("Unable to open pipe to iptables for rule listing.");
	}
	char buffer[128];
	std::string result = "";

	// Read pipe stream
	while(!feof(pipe)){
		if(fgets(buffer, 128, pipe) != NULL) result += buffer;
	}

	// Close stream
	pclose(pipe);

	// Read result line by line
	std::istringstream iss(result);
	std::string line;
	for(line = ""; getline(iss, line);){
		rules.insert(std::pair<unsigned int, std::string>(ruleInd,line));
		++ruleInd;
	}
	return rules;
}
