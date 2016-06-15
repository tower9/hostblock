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

Help
```
$ hostblock -h
```

Some simple statistics
```
$ sudo hostblock -s
```

TODO: Output list of blocked addresses

TODO: Manually remove address from data file

Start as daemon
```
$ sudo hostblock -d
```

Order daemon to reload configuration and datafile
```
$ sudo kill -SIGUSR1 <pid>
```

Requirements
------------

 - git or wget to get source from github
 - make
 - iptables
 - g++ >= 4.9

Contribution
------------

Source code is available on [GitHub](https://github.com/tower9/hostblock). Just fork, edit and submit pull request. Please be clear on commit messages.
