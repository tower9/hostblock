#!/sbin/runscript

extra_commands="stats list dlist"
description="HostBlock analyzes log files and updates access files to deny access"
description_stats="Shows statistics about blacklisted IPs"
description_list="Lists all blacklisted IPs"
description_dlist="Detailed list with all blacklisted IPs (includes count and last activity)"

depend() {
	use logger
}

start() {
	ebegin "Starting HostBlock daemon"
	start-stop-daemon --start -exec /usr/bin/hostblock --pidfile /var/run/hostblock.pid -- --daemon
	eend $?
}

stop() {
	ebegin "Stopping HostBlock daemon"
	start-stop-daemon --stop --pidfile /var/run/hostblock.pid
	eend $?
}

stats() {
	/usr/bin/hostblock --statistics
}

list() {
	/usr/bin/hostblock --list
}

dlist() {
	/usr/bin/hostblock --list --time --count
}
