/*
 * Simple class to work with iptables
 */

// Map
#include <map>
// Vector
#include <vector>

#ifndef HBIPTABLES_H
#define HBIPTABLES_H

namespace hb{

class Iptables{
	private:

	public:

		/*
		 * Constructor
		 */
		Iptables();

		/*
		 * Create new chain
		 */
		bool newChain(std::string chain);

		/*
		 * Append new rule(s) to the end of the chain
		 */
		bool append(std::string chain, std::string rule);
		bool append(std::string chain, std::vector<std::string>* rules);

		/*
		 * Insert rule(s) to the chain at specified position
		 */
		bool insert(std::string chain, std::string rule, int pos = 1);
		bool insert(std::string chain, std::vector<std::string>* rules, int pos = 1);

		/*
		 * Delete rule from chain
		 */
		bool remove(std::string chain, std::string rule);
		bool remove(std::string chain, std::vector<std::string>* rules);

		/*
		 * Get rule list
		 */
		std::map<unsigned int, std::string> listRules(std::string chain);

		/*
		 * Exec iptables any command with custom options
		 */
		bool command(std::string options);

		/*
		 * Exec iptables any command with custom options and return stdout in map each line as entry in map
		 */
		std::map<unsigned int, std::string> custom(std::string options);

};

}

#endif
