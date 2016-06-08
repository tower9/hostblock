/* 
 * Simple class to work with iptables
 */

#ifndef HBIPTABLES_H
#define HBIPTABLES_H

namespace hb{
	class Iptables{
		private:

		public:
			// Constructor
			Iptables();

			// Append chain with rule
			bool append(std::string chain, std::string rule);

			// Delete rule from chain
			bool remove(std::string chain, std::string rule);

			// Rule list
			std::map<unsigned int, std::string> listRules(std::string chain);
	};
}

#endif
