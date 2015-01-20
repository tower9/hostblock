# HostBlock

Automatic blocking of remote IP hosts attacking Apache Web server or SSH server. PHP script parses Apache access log files and SSHd log file to find suspicious activity and create blacklist of IP addresses to deny further access. Access to HTTPd is limited with .htaccess files (Apache will return 403 Forbidden) and access to SSHd is limited with /etc/hosts.deny (SSHd will refuse connect).

Script uses regex patterns to match suspicious entries in log files - you should modify them to match your needs. For example, I don't have phpmyadmin, so all HTTP requests with such URL I'm considering as suspicious.

## Features

 - Parses Apache Web server access_log files to find suspicious activity
 - Parses SSH server log file to find failed login attempts
 - Runs as daemon
 - Counts failed logins and suspicious activity for each offending IP address
 - Counts refused SSH connections for each IP address
 - Each IP address that has suspicious activity count over configured one is considered evil and is added to access files (/ets/hosts.deny or .htaccess files)
 - Daemon keeps track of parsed file size to parse only new bytes in file not the whole file each time (until file is rotated)
 - Keeps data of all suspicious IP addresses with suspicious/failed login attempt count and time of last attempt
 - Respects blacklist - IP addresses in this file will be considered as evil permanently, will add all these IP addresses to access files even if no suspicious activity is counted for any of them
 - Respects whitelist - IP addresses in this file will be ignored, will not add these IP addresses to access files (suspicious activity is still counted)
 - Allows to manually remove IP address from data file

## Setup

All provided commands are example - you might want to install this tool in your own directories.

 - Download hostblock sources from [GitHub](https://github.com/tower9/hostblock/archive/master.zip) or [PHP classes](http://www.phpclasses.org/browse/package/8458/download/targz.html) and extract in some temporary directory
 - In PHP include path directory (include_path directive in php.ini file) create directory hostblock and copy all files from include directory to newly created directory
```
# mkdir /usr/share/php5/hostblock
# cp include/* /usr/share/php5/hostblock/
```
 - Edit appropriate dist-cfg-*.php file and change paths to needed directories
```
# nano /usr/share/php5/hostblock/dist-cfg-gentoo.php
```
 - Rename dist-cfg-*.php to dist-cfg.php
```
# mv /usr/share/php5/hostblock/dist-cfg-gentoo.php /usr/share/php5/hostblock/dist-cfg.php
```
 - Copy hostblock.ini from config directory to CONFIG_PATH specified in dist-cfg file
```
# cp config/hostblock.ini /etc/hostblock.ini
```
 - Check and edit hostblock.ini if needed
```
# nano /etc/hostblock.ini
```
 - Choose a place where hostblock will store it's data, for example create directory hostblock in /var/lib/
```
# mkdir /var/lib/hostblock
```
 - Copy hostblock.php to WORKDIR_PATH specified in dist-cfg file
```
# cp hostblock.php /var/lib/hostblock/
```
 - Change hostblock.php file permissions to 775 (chmod 755 hostblock.php)
```
# chmod 755 /var/lib/hostblock/hostblock.php
```
 - Create symlink /usr/bin/hostblock to file hostblock.php
```
# ln -s /var/lib/hostblock/hostblock.php /usr/bin/hostblock
```

### Gentoo init script

 - Copy init script to /etc/init.d/
```
# cp init.d/gentoo-hostblock.sh /etc/init.d/hostblock
```
 - Change init script permissions to 755
```
# chmod 755 /etc/init.d/hostblock
```
 - Start daemon, note that it might take some time to start for a first time if specified log files are big
```
# /etc/init.d/hostblock start
```
 - To start hostblock automatically during system boot
```
# rc-update add hostblock default
```

### Systemd service file (RHEL7, OEL7, etc)

 - Copy systemd service file to /usr/lib/systemd/system/
```
# cp init.d/hostblock.service /usr/lib/systemd/system/hostblock.service
```
 - Start daemon (it might take some time to start)
```
# systemctl start hostblock
```
 - To start automatically during system boot
```
# systemctl enable hostblock.service
```

## Usage

To start (Gentoo)
```
# /etc/init.d/hostblock start
```
To start (RHEL7, OEL7, etc)
```
# systemctl start hostblock
```
To stop (Gentoo)
```
# /etc/init.d/hostblock stop
```
To stop (RHEL7, OEL7, etc)
```
# systemctl stop hostblock
```
Output usage
```
# hostblock -h
```
Statistics
```
# hostblock -s
```
List all blacklisted IP addresses
```
# hostblock -l
```
List all blacklisted IP addresses with suspicious activity count, refused SSH connect count and time of last activity
```
# hostblock -lct
```
Remove IP address from data file (removes suspicious activity count, refused SSH connect count and time of last activity)
```
# hostblock -r10.10.10.10
```
HostBlock also allows to parse old files to increase statistics

Manually parse Apache access log file
```
# hostblock -a -p/var/log/apache/access_log
```
Manually parse SSHd log file, that has data of 2013 year
```
# hostblock -e -p/var/log/messages -y2013
```
*Note, that by loading single file twice HostBlock will count same suspicious activity twice!*

## Story

I have an old laptop - HDD with bad blocks, keyboard without all keys, LCD with black areas over, etc. and I decided to put it in use - I'm using it as a Web server for tests. Didn't had to wait for a long time to start receiving suspicious HTTP requests and SSH authorizations on unexisting users - Internet never sleeps and guys are scanning it to find vulnerabilities all the time. Although there wasn't much interesting on this test server, I still didn't wanted for anyone to break into it. I started to look for some tools that would automatically deny access to such IP hosts. I found a very good tool called [DenyHosts](http://denyhosts.sourceforge.net). It monitors SSHd log file and automatically adds an entry in /etc/hosts.deny file after 3 failed login attempts from a single IP address. As I also wanted to check Apache access_log and deny access to my test pages I decided to write my own script. [DenyHosts](http://denyhosts.sourceforge.net) is written in Python and as I'm more familiar with PHP, I wrote from scratch in PHP. Also implemented functionality to load old log files and got nice statistics about suspicious activity before HostBlock was running. Found over 10k invalid SSH authorizations from some IP addresses in a few month period (small bruteforce attacks). Now that I have HostBlock running I usually don't get more than 20 invalid SSH authorizations from single IP address. With configuration, invalid authorization count can be limited even to 1, so it is up to you to decide how much failed authorizations you allow.

## Requirements

### PHP libraries

 - [PCNTL](http://www.php.net/manual/en/pcntl.installation.php)

### /etc/deny.hosts

deny.hosts file allow to secure services, that are using TCP Wrapper. TCP Wrapper is a host based Access Control List system, used to filter access to a Unix like server. It uses blacklist /etc/hosts.deny and whitelist /etc/hosts.allow. SSHd uses TCP Wrappers, if it is compiled with tcp_wrappers support, which means we can blacklist some IP addresses we do not like. For example if we see something like this in /var/log/messages - this is an actual entry on one of servers, where someone from Korea (or through Korea) is trying bruteforce against my SSHd:
```
Oct  2 09:16:15 keny sshd[12125]: Invalid user rootbull from 1.234.45.178
```
We can add this IP to /etc/hosts.deny and all further ssh connections from that IP address will be rejected.

*Note, that your SSH server might not respect entries in hosts.deny. Haven't investigated why, but un-commenting line ListenAddress 0.0.0.0 and /etc/init.d/sshd restart did the trick for me.*

To check if SSHd is actually respecting hosts.deny file, just add "sshd: 127.0.0.1" to this file and try to establish connection from localhost ($ ssh localhost). If you got something like this "ssh: Could not resolve hostname localhsot: Name or service not known", then all is fine and your SSHd is respecting hosts.deny file.

File hosts.deny is used by HostBlock to automatically block access to SSHd, so do test if your SSHd server actually respects this file.

### .htaccess

.htaccess files allow to deny access to some parts of your site. .htaccess is just a default name of this file, it can be changed with Apache [AccessFileName](http://httpd.apache.org/docs/2.2/mod/core.html#accessfilename) directive. Access files are meant to be used for per-directory configuration. Access file, containing one or more configuration directives, is placed in directory and directives apply to that directory, including all subdirectories. While this file allows to change a lot of configuration directives, HostBlock is currently interested only in "Deny from x.x.x.x", where x.x.x.x is suspicious IP address. Directive "Deny from" is self-explanatory, it denys access from specified IP address - Apache will return HTTP code 403 Forbidden.

Script searches for all lines that start with "Deny from" and checks if this IP address written in each line is in blacklist. If it is not in blacklist - line is removed. And the other way around, if blacklisted IP address is not found in access file, then new line "Deny from" is added at the end of file.

## Contribution

Source code is available on [GitHub](https://github.com/tower9/hostblock). Just fork, edit and submit pull request. Please be clear on commit messages.

## Future plans

 - Write init.d scripts and test on other distros
 - Add blacklisted IP addresses to iptables
 - Implement other server log file parsing, for example FTPd or email server
 - Create centralised repository with suspicious IP addresses, could also store more information about IP addresses there, such as suspicious activities (RAW data about activities), more statistics, etc
