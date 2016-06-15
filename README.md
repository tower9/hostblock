HostBlock
=========

Tool for log file monitoring and automatic blocking of remote hosts based on configured patterns.

I guess every admin of servers that are connected to internet have noticed some suspicious activity in log files. You can find some good suggestions to adjust server configuration so that it would be harder to get access to these servers, like completely disable root user SSH access, etc. Start with that ;) This is also a kind reminder to recheck config you made 10 years ago. Once finished and still interested to automatically monitor log files and adjust iptables, see Setup and Usage chapters.

Features
--------

 - Checks log files for suspicious activity and automatically adjusts iptables rules
 - Runs as daemon
 - Keeps some data about suspicious activity for some simple statistics and to compare with iptables
 - Daemon processes only new bytes from log files (until file is rotated)
 - Blacklist to manually blacklist some addresses
 - Whitelist to ignore some addresses
 - Allows to manually remove IP addresses from data file (clean slate)

Note, if this tool does not allow you to use iptables the way you like (is limiting you), please register issue, maybe some solution can be found. It would be nice not to limit iptables functionality that is being used if iptables are used together with hostblock. Maybe hostblock config should be extended for more flexible integration with iptables...

Setup
-----

 - Get source from github
```
$ git clone https://github.com/tower9/hostblock.git
```
 - This version of hostblock is currently only in branch 2.0 without version, so check out branch 2.0
```
$ git checkout 2.0
```
 - Compile
```
$ make
```
 - Install
```
$ sudo make install
```
 - Adjust configuration, review and adjust patterns
```
$ sudo vi /etc/hostblock.conf
```
 - To count refused connection count create new iptables chain and adjust hostblock configuration to use this new chain:
```
$ sudo iptables -N HB_LOG_AND_DROP
$ sudo iptables -A HB_LOG_AND_DROP -j LOG --log-prefix "IPTABLES-DROPPED: " --log-level 4
$ sudo iptables -A HB_LOG_AND_DROP -j DROP
```
 - TODO: Automatic startup script

Usage
-----

#### Help

To get short usage information:
```
$ hostblock -h
```

#### Statistics
Simple statistics:
```
$ sudo hostblock -s
```
For example, output:
```
Total suspicious IP address count: 1212

Top 5 most active addresses:
--------------------------------------------------------------------
     Address     | Count |   Score   | Refused |    Last activity   
--------------------------------------------------------------------
 10.10.10.10     | 62782 | 452025926 |    0    | 2016-05-12 18:47:14
 10.10.10.12     | 13451 | 96833655  |    0    | 2016-06-14 21:40:24
 10.10.10.16     | 12039 | 86655064  |    0    | 2016-06-13 21:55:21
 10.10.10.13     | 11958 | 86084822  |    0    | 2016-06-14 20:19:43
 192.168.0.100   | 10862 | 78204524  |    0    | 2016-06-13 17:10:05

Last activity:
--------------------------------------------------------------------
     Address     | Count |   Score   | Refused |    Last activity   
--------------------------------------------------------------------
 192.168.0.5     |   4   |   3600    |    0    | 2016-06-15 08:38:10
 10.10.10.11     |  541  |  1898777  |   90    | 2016-06-15 06:23:23
 192.168.5.143   |  48   |  185872   |    2    | 2016-06-15 06:23:23
 192.168.0.6     |  57   |  114681   |    1    | 2016-06-15 06:23:23
 10.10.10.180    |   1   |   3600    |    0    | 2016-06-14 22:23:38
```
 - Address - IP address of host from which some suspicious activity was detected
 - Count - suspicious activity count, how many times configured pattern was matched
 - Score - currently calculated score
 - Refused - dropped packet count by iptables
 - Last activity - Date and time of last activity, when pattern is matched this will show date and time when hostblock matched that pattern not time when line was written to log file

#### TODO: Output list of blocked addresses

#### TODO: Manually remove address from data file

#### Start as daemon

To start hostblock as background process to monitor log files and automatically adjust iptables:
```
$ sudo hostblock -d
```

#### Order daemon to reload configuration and datafile

After changing configuration you can either restart daemon or with SIGUSR1 signal inform daemon that configuration and datafile should be reloaded.
```
$ sudo kill -SIGUSR1 <pid>
```

Configuration
-------------
Default path for configuration file is /etc/hostblock.conf, which can be changed with environment variable HOSTBLOCK_CONFIG.

Main configuration is under [Global] section. Since log files can have different contents, configuration for them can be divided into [Log.*] sections, for example [Log.SSH].

More details can be found in default configuration file.

Requirements
------------

 - git or wget to get source from github
 - make
 - iptables
 - g++ >= 4.9

Contribution
------------

Source code is available on [GitHub](https://github.com/tower9/hostblock). Just fork, edit and submit pull request. Please be clear on commit messages.
