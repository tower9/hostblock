#!/usr/bin/php -q
<?php
/**
 * HostBlock v.0.1
 * 
 * Simple utility that parses log files and updates access files to deny access
 * to suspicious hosts.
 */

// Allow execution only from console
if(php_sapi_name() !== "cli"){
	echo "This script can be run only from console!";
	exit(1);
}

// Define allowed command line arguments
$shortopts = "hslctahp:y:d";
$longopts = array(
	'help',// usage
	'statistics',// statistics
	'list',// ip list (with count and/or ip)
	'count',// show activity count with list
	'time',// show last activity time with list
	'parse-apache-log',// parse Apache access log file
	'parse-ssh-log',// parse SSHd log file
	'path:',// path to log file for manual parsing
	'year:',// year for SSHd log parsing - this log file has time without year, to parse older log files this option was introduced
	'test',// run parsing as test - do not update IP data
	'daemon',// run script as daemon
);

if(isset($argv)){
	// Init some variables
	$showUsage = false;
	// Parse command line arguments
	$opts = getopt($shortopts,$longopts);
	
	// Include needed classes, config, initialize needed variables and objects
	if(isset($opts['statistics']) || isset($opts['s']) || isset($opts['list'])
		|| isset($opts['l']) || isset($opts['parse-apache-log']) || isset($opts['a'])
		|| isset($opts['parse-ssh-log'])  || isset($opts['h']) || isset($opts['daemon'])
		|| isset($opts['d'])){
		include_once "hostblock/dist-cfg.php";
		include_once "hostblock/Log.php";
		$log = new Log();
		$log->logDirectory = LOGDIR_PATH;
		include_once "hostblock/Stats.php";
		include_once "hostblock/ApacheAccessLogParser.php";
		include_once "hostblock/AccessUpdate.php";
		include_once "hostblock/SshdLogParser.php";
		$config = parse_ini_file(CONFIG_PATH);
		
		// Suspicious entry match count
		if(!isset($config['suspiciousentrymatchcount'])) $config['suspiciousentrymatchcount'] = 10;
		else $config['suspiciousentrymatchcount'] = (int)$config['suspiciousentrymatchcount'];
		
		// How long must a IP be kept in blacklist
		if(!isset($config['blacklisttime'])) $config['blacklisttime'] = 0;
		else $config['blacklisttime'] = (int)$config['blacklisttime'];
		
		// Whitelist
		if(!isset($config['whitelist'])) $config['whitelist'] = null;
		
		// Permanent blacklist
		if(!isset($config['blacklist'])) $config['blacklist'] = null;
		
		// Timezone
		if(!isset($config['timezone'])) $config['timezone'] = "UTC";
		date_default_timezone_set($config['timezone']);
		
		// Init stats object
		$stats = new Stats();
		$stats->suspiciousIpsPath = WORKDIR_PATH."/suspicious_ips";
		$stats->log = $log;
		$stats->suspiciousEntryMatchCount = $config['suspiciousentrymatchcount'];
		$stats->blacklistTime = $config['blacklisttime'];
		$stats->permanentBlacklistFile = $config['blacklist'];
		$stats->permanentWhitelistFile = $config['whitelist'];
		$stats->loadBlacklist();
	}
	
	if(isset($opts['statistics']) || isset($opts['s'])){
		// Output statistics
		$log->write("Preparing statistics...");
		
		// Get data from file
		$stats->load();
		// Calculate
		$stats->calculate();
		// Output data (formatted for console)
		$stats->output();
		
		$log->write("Statistics calculated");
		exit(0);
	} elseif(isset($opts['list']) || isset($opts['l'])){
		// Output blacklisted IPs
		$log->write("Preparing list of blacklisted IPs...");
		$count = false;
		$time = false;
		if(isset($opts['count']) || isset($opts['c'])) $count = true;
		if(isset($opts['time']) || isset($opts['t'])) $time = true;
		
		// Get data from file
		$stats->load();
		// Output data (each IP in new line)
		$stats->outputBlacklist($count, $time);
		
		$log->write("Blacklist returned");
		exit(0);
	} elseif(isset($opts['parse-apache-log']) || isset($opts['a'])){
		if(isset($opts['path']) || isset($opts['p'])){
			// Parse Apache access log file
			$path = null;
			if(isset($opts['path'])) $path = $opts['path'];
			if(isset($opts['p'])) $path = $opts['p'];
			if(!file_exists($path)){
				echo "Log file doesn't exist!\n";
				$log->write("Log file doesn't exist!","error");
				exit(1);
			}
			
			if(!isset($config['apacheaccesspaterns'])){
				$config['apacheaccesspaterns'] = array();
			}
			
			// Init Apache access log file parser
			$apacheAccessLogParser = new ApacheAccessLogParser();
			$apacheAccessLogParser->log = $log;
			$apacheAccessLogParser->suspiciousPatterns = $config['apacheaccesspaterns'];
			
			// Info about suspicious IPs
			$ipInfo = array();
			$data = @file_get_contents(WORKDIR_PATH."/suspicious_ips");
			if($data != false){
				$ipInfo = unserialize($data);
				$log->write("Suspicious IP data loaded!");
			}
			$stats->ipInfo = $ipInfo;
			
			echo "Suspicious IP addresses before processing: ".count($stats->ipInfo)."\n";
			echo "Blacklisted IP addresses before processing: ".$stats->getBlacklistedIpCount()."\n";
			
			$apacheAccessLogFile['path'] = $path;
			$apacheAccessLogFile['offset'] = 0;
			$updateHostData = false;
			$updateOffsets = false;
			$matchCount = $apacheAccessLogParser->parseFile($apacheAccessLogFile, $ipInfo, $updateHostData, $updateOffsets);
			
			// Update IP data
			$stats->ipInfo = $ipInfo;
			if(!isset($opts['test'])){
				$data = serialize($ipInfo);
				@file_put_contents(WORKDIR_PATH."/suspicious_ips", $data);
			}
			
			echo "Pattern match count: ".$matchCount."\n";
			echo "Suspicious IP addresses after processing: ".count($stats->ipInfo)."\n";
			echo "Blacklisted IP addresses after processing: ".$stats->getBlacklistedIpCount()."\n";
			
			$log->write("Apache access log file parsing finished.");
			if(!isset($opts['test'])){
				echo "IP address data updated! Please wait for daemon to reload IP data and update access files if needed.\n";
				$log->write("IP address data updated! Please wait for daemon to reload IP data and update access files if needed.");
			}
			exit(0);
			
		} else{
			echo "Path to log file not provided!\n";
			$showUsage = true;
		}
	} elseif(isset($opts['parse-ssh-log'])  || isset($opts['h'])){
		if(isset($opts['path']) || isset($opts['p'])){
			// Parse SSHd log file
			$path = null;
			if(isset($opts['path'])) $path = $opts['path'];
			if(isset($opts['p'])) $path = $opts['p'];
			if(!file_exists($path)){
				echo "Log file doesn't exist!\n";
				$log->write("Log file doesn't exist!","error");
				exit(1);
			}
			$year = date("Y");
			if(isset($opts['year'])) $year = (int)$opts['year'];
			if(isset($opts['y'])) $year = (int)$opts['y'];
			
			// Init SSHd log file parser
			$sshdLogParser = new SshdLogParser();
			$sshdLogParser->log = $log;
			if(isset($config['sshformats']) && count($config['sshformats']) > 0){
				$sshdLogParser->formats = $config['sshformats'];
			}
			if(isset($config['sshrefusedformat']) && !empty($config['sshrefusedformat'])){
				$sshdLogParser->refusedFormat = $config['sshrefusedformat'];
			}
			
			$sshdLogFile = array();
			$sshdLogFile['path'] = $path;
			$sshdLogFile['offset'] = 0;
			
			// Info about suspicious IPs
			$ipInfo = array();
			$data = @file_get_contents(WORKDIR_PATH."/suspicious_ips");
			if($data != false){
				$ipInfo = unserialize($data);
				$log->write("Suspicious IP address data loaded!");
			}
			$stats->ipInfo = $ipInfo;
			
			echo "Suspicious IP addresses before parsing: ".count($stats->ipInfo)."\n";
			echo "Blacklisted IP addresses before parsing: ".$stats->getBlacklistedIpCount()."\n";
			echo "Total refused SSH authorization count before parsing: ".$stats->getTotalRefusedConnectCount()."\n";
			
			// Check for entries in SSHd log file
			$updateHostData = false;
			$updateOffsets = false;
			$matchCount = $sshdLogParser->parseFile($sshdLogFile, $ipInfo, $updateHostData, $updateOffsets, $year);
			
			// Update IP data
			$stats->ipInfo = $ipInfo;
			if(!isset($opts['test'])){
				$data = serialize($ipInfo);
				@file_put_contents(WORKDIR_PATH."/suspicious_ips", $data);
			}
			
			echo "Pattern match count: ".$matchCount."\n";
			echo "Suspicious IP addresses after parsing: ".count($stats->ipInfo)."\n";
			echo "Blacklisted IP addresses after parsing: ".$stats->getBlacklistedIpCount()."\n";
			echo "Total refused SSH authorization count after parsing: ".$stats->getTotalRefusedConnectCount()."\n";
			
			$log->write("SSHd log file parsing finished.");
			if(!isset($opts['test'])){
				echo "IP address data updated! Please wait for daemon to reload IP data and update access files if needed.\n";
				$log->write("IP address data updated! Please wait for daemon to reload IP data and update access files if needed.");
			}
			exit(0);
		} else{
			echo "Path to log file not provided!\n";
			$showUsage = true;
		}
	} elseif(isset($opts['daemon']) || isset($opts['d'])){
		// Start as daemon process
		$log->write("Starting daemon process...");
		
		// Check if process is already running
		if(file_exists(PID_PATH)){
			echo "Another instance of hostblock is already running!";
			$log->write("Another instance of hostblock is already running!","error");
			exit(1);
		}
		
		// Fork currently running process
		$pid = pcntl_fork();
		if($pid == -1){// Fork failed
			echo "Failed to fork process!";
			$log->write("Failed to fork process!","error");
			exit(1);
		} elseif($pid){// We are parent (pid>0)
			// Write PID to file
			$f = @fopen(PID_PATH,"w");
			if($f){
				@fwrite($f,$pid);
				@fclose($f);
			}
			
			// Fork succeeded, exit
			exit(0);
		} else{// We are children (pid==0)
			// Variable for main loop, will exit loop when false
			$running = true;
			
			// tick required for signal handler
			declare(ticks = 1);
			
			// Define signal handler
			function signal_handler($signalNumber){
				global $running;
				switch($signalNumber){
					case SIGTERM:
						// Handle shutdown
						$running = false;
						break;
				}
			}
			
			// Install signal handler
			$log->write("Registering signal handler...");
			pcntl_signal(SIGTERM,"signal_handler");
			
			// Log file parse interval
			if(!isset($config['logparseinterval'])) $config['logparseinterval'] = 60;
			else $config['logparseinterval'] = (int)$config['logparseinterval'];
			
			// Access file update interval
			if(!isset($config['blacklistupdateinterval'])) $config['blacklistupdateinterval'] = 60;
			else $config['blacklistupdateinterval'] = (int)$config['blacklistupdateinterval'];
			
			// Get stored log file offsets
			$data = @file_get_contents(WORKDIR_PATH."/offsets");
			if($data != false){
				$offsets = unserialize($data);
				$log->write("Log file offset data loaded!");
			}
			
			// Apache access log file configuration
			$apacheAccessLogFiles = array();
			if(!isset($config['apacheaccesslogs'])){
				$config['apacheaccesslogs'] = array();
			}
			if(!isset($config['apacheaccesslogformats'])){
				$config['apacheaccesslogformats'] = array();
			}
			if(count($config['apacheaccesslogs']) > 0){
				foreach($config['apacheaccesslogs'] as $k => $v){
					$offset = 0;
					if(isset($offsets) && isset($offsets[$v])){
						$offset = $offsets[$v];
					}
					$format = "%h %l %u %t \"%r\" %s %b";
					if(isset($config['apacheaccesslogformats'][$k]) && !empty($config['apacheaccesslogformats'][$k])){
						$format = $config['apacheaccesslogformats'][$k];
					}
					$apacheAccessLogFiles[] = array(
						'path' => $v,
						'offset' => $offset,
						'format' => $format,
					);
				}
			}
			if(!isset($config['apacheaccesspaterns'])){
				$config['apacheaccesspaterns'] = array();
			}
			if(!isset($config['htaccessfiles'])){
				$config['htaccessfiles'] = array();
			}
			
			// SSHd log file config
			$sshdLogFile = array();
			if(isset($config['sshlog'])){
				$sshdLogFile['path'] = $config['sshlog'];
				$sshdLogFile['offset'] = 0;
				if(isset($offsets) && isset($offsets[$sshdLogFile['path']])) $sshdLogFile['offset'] = $offsets[$sshdLogFile['path']];
			}
			
			// Init Apache access log file parser
			$apacheAccessLogParser = new ApacheAccessLogParser();
			$apacheAccessLogParser->log = $log;
			$apacheAccessLogParser->suspiciousPatterns = $config['apacheaccesspaterns'];
			
			// Init Apache access file updater
			$accessUpdater = new AccessUpdate();
			$accessUpdater->log = $log;
			
			// Init SSHd log file parser
			$sshdLogParser = new SshdLogParser();
			$sshdLogParser->log = $log;
			if(isset($config['sshformats']) && count($config['sshformats']) > 0){
				$sshdLogParser->formats = $config['sshformats'];
			}
			if(isset($config['sshrefusedformat']) && !empty($config['sshrefusedformat'])){
				$sshdLogParser->refusedFormat = $config['sshrefusedformat'];
			}
			
			// Info about suspicious IPs
			$ipInfo = array();
			$data = @file_get_contents(WORKDIR_PATH."/suspicious_ips");
			if($data != false){
				$ipInfo = unserialize($data);
				$log->write("Suspicious IP address data loaded!");
			}
			$stats->ipInfo = $ipInfo;
			
			// Main loop
			$lastParseTime = time()-$config['logparseinterval'];
			$lastUpdateTime = time()-$config['blacklistupdateinterval'];
			$updateHostData = false;
			$updateOffsets = false;
			$newMatchCount = 0;
			$updateAccessFiles = false;
			$blacklistedIpCount = $stats->getBlacklistedIpCount();
			$lastFileCheckTime = time();
			if(file_exists(WORKDIR_PATH."/suspicious_ips")) $ipInfoMTime = filemtime(WORKDIR_PATH."/suspicious_ips");
			if(!is_null($config['blacklist'])) $blacklistMTime = filemtime($config['blacklist']);
			if(!is_null($config['whitelist'])) $whitelistMTime = filemtime($config['whitelist']);
			while($running){
				// Check each 60 seconds if data files are updated and reload if needed
				if(time() - $lastFileCheckTime >= 60){
					// Suspicious IP data
					if(file_exists(WORKDIR_PATH."/suspicious_ips")){
						$ipInfoMTimeNew = filemtime(WORKDIR_PATH."/suspicious_ips");
						if($ipInfoMTime != $ipInfoMTimeNew){
							$log->write("Suspicious IP address data has been changed, reloading data for deamon!");
							$data = @file_get_contents(WORKDIR_PATH."/suspicious_ips");
							if($data != false){
								$ipInfo = unserialize($data);
								$log->write("Suspicious IP data loaded!");
							}
							$stats->ipInfo = $ipInfo;
							if($blacklistedIpCount != $stats->getBlacklistedIpCount()){
								$updateAccessFiles = true;
								$blacklistedIpCount = $stats->getBlacklistedIpCount();
							}
							$ipInfoMTime = $ipInfoMTimeNew;
						}
					}
					// Blacklist/whitelist
					$reloadStatsBlacklist = false;
					if(!is_null($config['blacklist'])){
						$blacklistMTimeNew = filemtime($config['blacklist']);
						if($blacklistMTime != $blacklistMTimeNew){
							$reloadStatsBlacklist = true;
							$blacklistMTime = $blacklistMTimeNew;
						}
					}
					if(!is_null($config['whitelist'])){
						$whitelistMTimeNew = filemtime($config['whitelist']);
						if($whitelistMTime != $whitelistMTimeNew){
							$reloadStatsBlacklist = true;
							$whitelistMTime = $whitelistMTimeNew;
						}
					}
					if($reloadStatsBlacklist){
						$log->write("Whitelist/blacklist has been changed, reloading data for deamon!");
						$stats->loadBlacklist();
						$reloadStatsBlacklist = false;
						$updateAccessFiles = true;
						$blacklistedIpCount = $stats->getBlacklistedIpCount();
					}
					$lastFileCheckTime = time();
				}
				
				// If it is time to check log files for new entries
				if(time() - $lastParseTime >= $config['logparseinterval']){
					// Loop through all defined apache log files
					if(count($apacheAccessLogFiles) > 0){
						foreach($apacheAccessLogFiles as &$apacheAccessLogFile){
							// Check for new entries in file
							$newMatchCount += $apacheAccessLogParser->parseFile($apacheAccessLogFile, $ipInfo, $updateHostData, $updateOffsets);
						}
					}
					
					// Check for new entries in SSHd log file
					if(isset($sshdLogFile['path'])){
						$newMatchCount += $sshdLogParser->parseFile($sshdLogFile, $ipInfo, $updateHostData, $updateOffsets);
					}
					
					// Update host data
					if($updateHostData == true){
						$data = serialize($ipInfo);
						@file_put_contents(WORKDIR_PATH."/suspicious_ips", $data);
						$ipInfoMTime = filemtime(WORKDIR_PATH."/suspicious_ips");
						$updateHostData = false;
						// Check if blacklisted IP count differs
						// Here might be a bug if we have +1 because of activity and -1 because of time in a same time
						$stats->ipInfo = $ipInfo;
						if($blacklistedIpCount != $stats->getBlacklistedIpCount()){
							$updateAccessFiles = true;
							$blacklistedIpCount = $stats->getBlacklistedIpCount();
						}
						$log->write("Suspicious IP address data updated!");
					}
					
					// Update offsets
					if($updateOffsets == true){
						$offsets = array();
						foreach($apacheAccessLogFiles as &$apacheAccessLogFile){
							$offsets[$apacheAccessLogFile['path']] = $apacheAccessLogFile['offset'];
						}
						if(isset($sshdLogFile['path'])){
							$offsets[$sshdLogFile['path']] = $sshdLogFile['offset'];
						}
						$offsets = serialize($offsets);
						@file_put_contents(WORKDIR_PATH."/offsets", $offsets);
						$updateOffsets = false;
					}
					
					// Info in log file if we have new pattern matches
					if($newMatchCount > 0){
						$log->write("Pattern match count: ".$newMatchCount);
						$newMatchCount = 0;
					}
					
					// Update last parse time
					$lastParseTime = time();
				}
				
				// If it is time to check if update to blacklist is needed
				if(time() - $lastUpdateTime >= $config['blacklistupdateinterval']){
					if($updateAccessFiles == true){
						// Update white&black lists
						$stats->loadBlacklist();
						// Get blacklisted IPs
						$blacklistedIps = $stats->getBlacklistedIps();
						// If we need to update .htaccess files
						if(count($config['htaccessfiles']) > 0){
							foreach($config['htaccessfiles'] as &$apacheAccessFile){
								$accessUpdater->updateApacheAccessFile($apacheAccessFile, $blacklistedIps);
							}
							$log->write("Apache access files updated!");
							$updateAccessFiles = false;
						}
						
						// If we need to update hosts.deny files
						if(isset($config['hostsdenyfile']) && !empty($config['hostsdenyfile'])){
							$accessUpdater->updateHostsDenyFile($config['hostsdenyfile'], $blacklistedIps);
							$log->write("hosts.deny file updated!");
							$updateAccessFiles = false;
						}
					}
					
					// Update last update time
					$lastUpdateTime = time();
				}
				
				// Sleep half a second before next iteration
				usleep(500000);
			}
			$log->write("Total suspicious IP addresses: ".count($ipInfo));
			$log->write("Shutdown");
			exit(0);
		}
	} else{
		$showUsage = true;
	}
	if($showUsage){
		echo "HostBlock v.0.1\n\n";
		echo "Usage:\n";
		echo "hostblock [-h | --help] [-s | --statistics] [-l | --list [-c | --count] [-t | --time]] [-a -p<path> | --parse-apache-access-log --path=<path>] [-h -p<path> -y<year> | --parse-ssh-log --path=<path> --year=<year>] [-d | --daemon]\n";
		echo '
--help                                      - show this help information
--statistics                                - show statistics
--list                                      - show list of blacklisted IP addresses
--list --count                              - show list of blacklisted IP addresses with suspicious activity count
--list --time                               - show list of blacklisted IP addresses with last suspicious activity time
--list --count --time                       - show list of blacklisted IP addresses with suspicious activity count and last suspicious activity time
--parse-apache-log --path=<path>            - parse Apache access log file
--parse-ssh-log --path=<path> --year=<year> - parse SSHd log file
--daemon                                    - run as daemon
';
	}
}
?>