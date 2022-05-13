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
		bool newChain(std::string chain, int version = 4);

		/*
		 * Append new rule(s) to the end of the chain
		 */
		bool append(std::string chain, std::string rule, int version = 4);
		bool append(std::string chain, std::vector<std::string>* rules, int version = 4);

		/*
		 * Insert rule(s) to the chain at specified position
		 */
		bool insert(std::string chain, std::string rule, int version = 4, int pos = 1);
		bool insert(std::string chain, std::vector<std::string>* rules, int version = 4, int pos = 1);

		/*
		 * Delete rule from chain
		 */
		bool remove(std::string chain, std::string rule, int version = 4);
		bool remove(std::string chain, std::vector<std::string>* rules, int version = 4);

		/*
		 * Get rule list
		 */
		void listRules(std::string chain, std::vector<std::string>& rules, int version = 4);

		/*
		 * Exec iptables any command with custom options
		 */
		bool command(std::string options, int version = 4);

		/*
		 * Exec iptables any command with custom options and return stdout in map each line as entry in map
		 */
		std::map<unsigned int, std::string> custom(std::string options, int version = 4);

};

}

#endif
