
Tool for log file monitoring and automatic blocking of remote IP hosts based on configured patterns.

# Features

 - Checks log files for suspicious activity and automatically adjusts iptables rules
 - Runs as daemon
 - Keeps local data about suspicious activity for some simple statistics and to compare with iptables
 - Daemon processes only new bytes from log files and detects if log file is rotated
 - Blacklist to manually blacklist addresses
 - Whitelist to ignore addresses
 - Remove IP address from local data file
 - Automatic reporting and blacklist download from AbuseIPDB (API v2)

# Setup

Get source from github
```
$ git clone https://github.com/tower9/hostblock.git
```

Checkout latest tag
```
$ git checkout `git describe --abbrev=0`
```

Compile
```
$ make
```

Install
```
$ sudo make install
```

Review and adjust patterns in config file
```
$ sudo vi /etc/hostblock.conf
```

To count refused connection count create new iptables chain and adjust hostblock configuration to use this new chain
```
$ sudo iptables -N HB_LOG_AND_DROP
$ sudo iptables -A HB_LOG_AND_DROP -j LOG --log-prefix "IPTABLES-DROPPED: " --log-level 4
$ sudo iptables -A HB_LOG_AND_DROP -j DROP
$ sudo ip6tables -N HB_LOG_AND_DROP
$ sudo ip6tables -A HB_LOG_AND_DROP -j LOG --log-prefix "IPTABLES-DROPPED: " --log-level 4
$ sudo ip6tables -A HB_LOG_AND_DROP -j DROP
```

Before first hostblock start consider truncating/rotating/archiving log files so that hostblock starts monitoring log files from scratch. Otherwise it will take a while to start, depending on log file size can even take couple of hours. Also if historical data will be processed, last activity of all these addresses will be with date of hostblock first start and a lot of addresses can be blacklisted although they might no longer be malicious.

It is recommended to turn off AbuseIPDB integration for first start to avoid old/outdated suspicious activity reporting. Easiest way to turn off AbuseIPDB reporting functionality is to comment out line containing API key.

`make install` should detect if systemd or upstart is used and install appropriate service script/configuration.

If systemd is used, start hostblock
```
$ sudo systemctl start hostblock
```

If systemd is used, enable service to automatically start hostblock after reboot
```
$ sudo systemctl enable hostblock
```

If upstart is used, start hostblock
```
$ sudo service hostblock start
```

If systemctl or upstart is not available, write your own init script or start hostblock manually as a background process to monitor and automatically block access
```
$ sudo hostblock -d
```

# Usage

### Help

Short usage information
```
$ hostblock -h
```

### Currently loaded configuration
Output currently loaded configuration
```
$ sudo hostblock -p
```
Note, output is in the same format as configuration file thus can be used to export current configuration to use for other hosts.

### Statistics
Simple statistics
```
$ sudo hostblock -s
```
Output example
```
Total suspicious IP address count: 1212
AbuseIPDB blacklist size: 10000
Last AbuseIPDB blacklist sync time: 2019-05-20 17:17:17
AbuseIPDB blacklist generation time: 2019-05-20 17:00:02
Total suspicious activity: 2424
Total refused: 1313
Total whitelisted: 5
Total blacklisted: 44
Total blocked: 121

Top 5 most active addresses:
-----------------------------------------------------------------------------------------
    Address    | Count |   Score   | Refused |    Last activity    |       Status        
-----------------------------------------------------------------------------------------
 10.10.10.10   | 62782 | 452025926 |    0    | 2019-05-12 18:47:14 | 2033-10-10 13:13:40 
 10.10.10.12   | 13451 | 96833655  |    0    | 2019-06-14 21:40:24 | 2021-07-09 15:14:13 
 10.10.10.16   | 12039 | 86655064  |    0    | 2019-06-13 21:55:21 | 2021-03-13 20:40:60 
 10.10.10.13   | 11958 | 86084822  |    0    | 2019-06-14 20:19:43 | 2021-03-07 04:40:05 
 192.168.0.100 | 10862 | 78204524  |    0    | 2019-06-13 17:10:05 | 2020-12-05 20:30:49 

Last activity:
-----------------------------------------------------------------------------------------
    Address    | Count |   Score   | Refused |    Last activity    |       Status        
-----------------------------------------------------------------------------------------
 192.168.0.5   |   4   |   3600    |    0    | 2019-06-15 08:38:10 |                     
 10.10.10.11   |  541  |  1898777  |   90    | 2019-06-15 06:23:23 | 2019-06-15 14:00:03 
 192.168.5.143 |  48   |  185872   |    2    | 2019-06-15 06:23:23 |                     
 192.168.0.6   |  57   |  114681   |    1    | 2019-06-15 06:23:23 | whitelisted         
 10.10.10.180  |   1   |   3600    |    0    | 2019-06-14 22:23:38 |                     
```
 - Address - IP address of host from which some suspicious activity was detected
 - Count - suspicious activity count, how many times configured pattern was matched
 - Score - currently calculated score
 - Refused - dropped packet count by iptables, will count only with appripriate configuration (separate iptables chain, appropriate block rule for hostblock and pattern)
 - Last activity - Date and time of last activity, when pattern is matched this will show date and time when hostblock matched that pattern not time when line was written to log file
 - Status - whether address is whitelisted, blacklisted, blocked or, if score multiplier is configured, then date and time until rule should be removed from iptables

### Output list of blocked addresses

List all blocked addresses
```
$ sudo hostblock -l
```

List all addresses
```
$ sudo hostblock -la
```

List all blocked addresses with activity count, score and refused count
```
$ sudo hostblock -lc
```

List all blocked addresses with last activity time
```
$ sudo hostblock -lt
```

### Blacklist

To blacklist address - keep iptables rule regardless of suspicious activity
```
$ sudo hostblock -b10.10.10.10
```

### Whitelist

To whitelist address - do not create iptables rule even if suspicious activity is detected
```
$ sudo hostblock -w192.168.0.2
```

### Remove address from data file

To delete all information about address
```
$ sudo hostblock -r192.168.0.3
```

### Order daemon to reload configuration and datafile

After changing configuration you can either restart daemon or with SIGUSR1 signal inform daemon that configuration and datafile should be reloaded.
```
$ sudo kill -SIGUSR1 <pid>
```

# Configuration

Default path for configuration file is /etc/hostblock.conf, which can be changed with environment variable HOSTBLOCK_CONFIG.

Main configuration is under [Global] section. Log file contents are different for each service and can have different log levels. Configuration can be divided into [Log.\*] sections to specify separate patterns for each log group, for example [Log.SSH].

For more details see comments in [default configuration file](config/hostblock.conf).

## AbuseIPDB

[AbuseIPDB](https://www.abuseipdb.com) is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It is a database of reports of an IP addresses associated with malicious activity and allows it's users to report or check reports related to IP addresses.

Hostblock allows to automatically report suspicious activity to AbuseIPDB using API v2.

Login into your AbuseIPDB account and create an [API key](https://www.abuseipdb.com/account/api). Specify generated key in configuration file (/etc/hostblock.conf)
```
## AbuseIPDB API Key
abuseipdb.api.key = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

You can choose to either report all matched suspicious activity to AbuseIPDB
```
## Whether to report all matches to AbuseIPDB (true|false, default false)
abuseipdb.report.all = true
```

Or to specify at log group level to report all matched suspicious activity any of patterns under specific log group/groups
```
## AbuseIPDB log group level configuration (overrides global setting)
abuseipdb.report.all = true
```

Or to specify at pattern level to report all matched suspicious activity matching specific pattern/patterns
```
log.refused.pattern = ^.+? kernel: \[\s?\d+\.\d+\] IPTABLES-DROPPED: .+? SRC=%i .+? DPT=22 .+?
log.refused.score = 5
log.abuseipdb.report = true
```

See description of other available parameters like categories to report, comment and hostname masking in [default configuration file](config/hostblock.conf).

Hostblock also allows to synchronize with AbuseIPDB blacklist - get blacklist from AbuseIPDB API v2 and adjust iptables rules based on blacklist.

Specify synchronization interval
```
## Interval to sync AbuseIPDB blacklist, use 0 to disable (seconds, default 0)
## Note, it is recommended to sync no more often than once per 24h, i.e. 86400 seconds
abuseipdb.blacklist.interval = 0
```

And specify min score needed to create iptables rule
```
abuseipdb.block.score = 90
```

# Requirements

For compilation
 - git or wget to get source from github
 - make
 - iptables
 - g++ >= 4.9
 - libcurl
 - libjsoncpp1

### Debian

libjsoncpp
```
# apt install libjsoncpp-dev
```

libcurl openssl version (see available options by installing libcurl-dev)
```
# apt install libcurl4-openssl-dev
```

### CentOS
```
# yum install libcurl-devel
```
```
# yum install jsoncpp-devel
```

### Gentoo
libjsoncpp
```
# emerge dev-libs/jsoncpp
```

# Contribution

Source code is available on [GitHub](https://github.com/tower9/hostblock). Just fork, edit and submit pull request. Please be clear on commit messages.
