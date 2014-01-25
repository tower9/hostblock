# HostBlock

Automatic blocking of remote IP hosts attacking Apache or SSHd. PHP script parses Apache access log files and SSHd log file to find suspicious activity and create blacklist of IP addresses to deny further access. Access to HTTPd is limited with .htaccess files (Apache will return 403 Forbidden) and access to SSHd is limited with /etc/hosts.deny (SSHd will refuse connect).

Script uses regex patterns to match suspicious entries in log files - you should modify them to match your needs. For example, I don't have phpmyadmin, so all HTTP requests with such URL I'm considering as suspicious.

## Story

I have an old laptop - HDD with bad blocks, keyboard without all keys, LCD with black areas over, etc. and I decided to put it in use and now I'm using it as an Web server for tests. Didn't had to wait for a long time to start receiving suspicious HTTP requests and SSH authorizations on unexisting users - Internet never sleeps and guys are scanning it to find vulnerabilities all the time. I didn't wanted anyone to break into my test server, so I started to look for some tools that would automatically deny access to such IP hosts. I found a very good tool called [DenyHosts](http://denyhosts.sourceforge.net). It monitors SSHd log file and automatically adds an entry in /etc/hosts.deny file after 3 failed login attempts from a single IP address. As I also wanted to check apache access_log and deny access to my test pages I decided to write my own script. [DenyHosts](http://denyhosts.sourceforge.net) is written in Python and as I'm more familiar with PHP, I wrote from scratch in PHP. Also implemented functionality to load old log files and got nice statistics about suspicious activity, before HostBlock was running. Found over 10k invalid SSH authorizations from some IP addresses in a few month period (small bruteforce attacks). You can never know if attacker don't get lucky with bruteforce, especially if you ignore such messages in log files. Now that I have HostBlock running I usually don't get more than 20 invalid SSH authorizations from single IP address. With configuration, invalid authorization count can be limited even to 1, so it is up to you to decide how much invalid authorizations you allow.

## Requirements

### PHP libraries

 - [PCNTL](http://www.php.net/manual/en/pcntl.installation.php)

### /etc/deny.hosts

deny.hosts file allow to secure some services, which are using TCP Wrapper. The blacklist file is /etc/hosts.deny and whitelist file is /etc/hosts.allow. SSHd uses TCP Wrappers (if it is compiled with tcp_wrappers support), which means we can blacklist some IPs we do not like. For example if we see something like this in /var/log/messages - this is an actual entry on one of servers, where someone from Korea is trying bruteforce SSHd:
```
Oct  2 09:16:15 keny sshd[12125]: Invalid user rootbull from 1.234.45.178
```
We can add this IP to /etc/hosts.deny and all ssh connections from that IP address will be rejected.

*Note, that your SSH server might not respect entries in hosts.deny, haven't investigated why, but un-commenting line ListenAddress 0.0.0.0 and /etc/init.d/sshd restart helped me.*

To check if SSHd is actually respecting hosts.deny file, just add "sshd: 127.0.0.1" to this file and try to establish connection from localhost ($ ssh localhost). If you got something like this "ssh: Could not resolve hostname localhsot: Name or service not known", then all is fine and your sshd is respecting hosts.deny file.

File hosts.deny is used by HostBlock to automatically block access to SSHd, so do test if your SSHd server actually respects this file.

## Features

 - Parses access_log files to find suspicious activity
 - Parses /var/log/messages to find failed login attempts
 - Runs as daemon
 - Counts failed logins and suspicious activity for each offending IP address
 - Each IP address that has count over defined one is considered evil and stored in access files (/ets/hosts.deny or .htaccess files)
 - Daemon keeps track of parsed file offset to parse only new bytes in file not the whole file each time (until file is rotated)
 - Keeps data of all suspicious IP addresses with suspicious/failed login attempt count and date of last attempt
 - Respects blacklist - IP addresses in this file will be considered as evil permanently
 - Respects whitelist - IP addresses in this file will be ignored

## Future plans

 - Write init.d scripts and test on other distros
 - Add blacklisted IP addresses to iptables
 - Add functionality to remove suspicious IP addresses from data files
 - Implement other server log file parsing, for example FTPd or email server
 - Create centralised repository with suspicious IP addresses, could also store more information about IP addresses there, such as suspicious activities (RAW data about activities), more statistics, etc
