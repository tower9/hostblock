HostBlock
=========

WORK IN PROGRESS, NOT YET USABLE!

Tool for log file monitoring and automatic blocking of remote hosts based on configured patterns.

I guess every admin of servers that are connected to internet have noticed some suspicious activity in log files. You can find some good suggestions to adjust server configuration so that it would be harder to get access to these servers, like completely disable root user SSH access, etc. Start with that ;) This is also a kind reminder to recheck config you made 10 years ago.

A while ago I wrote some simple script to monitor log files and automatically add IP addresses to /etc/hosts.deny (requres TCP wrappers for OpenSSH) and .htaccess files. TCP wrapper support was dropped and I decided that using iptables to drop such connections would be better way to block access. And it has been a while since I wrote anything in C++ so I decided to refresh my C++ knowledge.

Features
--------

 - 

Setup
-----

 - 

Requirements
------------

 -

Contribution
------------

Source code is available on [GitHub](https://github.com/tower9/hostblock). Just fork, edit and submit pull request. Please be clear on commit messages.

Future plans
------------

 - 
