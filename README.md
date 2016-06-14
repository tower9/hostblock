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
 - Compile
```
$ make
```
 - Install
```
$ sudo make install
```
 - Adjust configuration
```
$ sudo vi /etc/hostblock.conf
```
 - To be continued...

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

To be continued...

Requirements
------------

 - git or wget to get source from github
 - make
 - iptables
 - g++ >= 4.9

Contribution
------------

Source code is available on [GitHub](https://github.com/tower9/hostblock). Just fork, edit and submit pull request. Please be clear on commit messages.
