<?php
class Stats{
	// Path to file with IP info
	public $suspiciousIpsPath = "";
	// Object for writing to log files
	public $log = null;
	// How many matches must an IP have to be in blacklist
	public $suspiciousEntryMatchCount = 5;
	// For how long time to keep IP in blacklist
	public $blacklistTime = 0;
	// Array with IP information
	public $ipInfo = array();
	// Array with statistics data
	private $data = array();
	// Permanent blacklist file
	public $permanentBlacklistFile = "";
	// Permanent whitelist file
	public $permanentWhitelistFile = "";
	// IPs from blacklist file
	private $include = array();
	// IPs from whitelist file
	private $exclude = array();
	
	/**
	 * Load data about IPs that needs to be perminately included or excluded
	 */
	public function loadBlacklist(){
		// Clear blacklist/whitelist arrays
		$this->include = array();
		$this->exclude = array();
		// Read blacklist
		if(!is_null($this->permanentBlacklistFile)){
			$f = @fopen($this->permanentBlacklistFile,"r");
			if($f){
				while(!feof($f)){
					$line = trim(fgets($f,4096));
					if(ip2long($line) !== false){
						if(!in_array($line,$this->include)){
							$this->include[] = $line;
						} else{
							$this->log->write("Duplicate IP address ".$line." in permanent blacklist file!");
						}
					}
				}
				@fclose($f);
			}
		}
		// Read whitelist
		if(!is_null($this->permanentWhitelistFile)){
			$f = @fopen($this->permanentWhitelistFile,"r");
			if($f){
				while(!feof($f)){
					$line = trim(fgets($f,4096));
					if(ip2long($line) !== false){
						if(!in_array($line,$this->exclude)){
							$this->exclude[] = $line;
						} else{
							$this->log->write("Duplicate IP address ".$line." in permanent whitelist file!");
						}
					}
				}
				@fclose($f);
			}
		}
	}
	
	/**
	 * Load data about suspicious IPs
	 */
	public function load(){
		// Read IP data
		$data = @file_get_contents($this->suspiciousIpsPath);
		if($data != false){
			$this->ipInfo = unserialize($data);
		} else{
			$this->log->write("Unable to load IP data!","error");
		}
	}
	
	/**
	 * Calculate statistics
	 */
	public function calculate(){
		$this->data = array();
		$currentTime = time();
		if(count($this->ipInfo) > 0){
			// Init data
			$this->data['blacklisted_ip_count'] = count($this->include);
			$this->data['top5'] = array();
			$this->data['top5']['ip'] = array();
			$this->data['top5']['count'] = array();
			$this->data['top5']['refused'] = array();
			$this->data['top5']['lastactivity'] = array();
			$this->data['last5'] = array();
			$this->data['last5']['ip'] = array();
			$this->data['last5']['count'] = array();
			$this->data['last5']['refused'] = array();
			$this->data['last5']['lastactivity'] = array();
			
			// Loop through all IPs
			foreach($this->ipInfo as $k => $v){
				if(!isset($v['refused'])) $v['refused'] = 0;
				
				// Blacklisted IP count
				if($v['count'] >= $this->suspiciousEntryMatchCount && (($currentTime - $v['lastactivity']) <= $this->blacklistTime || $this->blacklistTime == 0) && !in_array($k,$this->exclude)){
					$this->data['blacklisted_ip_count']++;
				}
				
				// Last 5 IPs
				if(count($this->data['last5']['ip']) < 5){// First we fill up last5 array
					$this->data['last5']['ip'][] = $k;
					$this->data['last5']['count'][] = $v['count'];
					$this->data['last5']['refused'][] = $v['refused'];
					$this->data['last5']['lastactivity'][] = $v['lastactivity'];
				} else{// Then we update with IPs that have more recent activity
					$keys = array_keys($this->data['last5']['lastactivity'],min($this->data['last5']['lastactivity']));
					if(count($keys) > 0){
						if($this->data['last5']['lastactivity'][$keys[0]] < $v['lastactivity']){
							$this->data['last5']['ip'][$keys[0]] = $k;
							$this->data['last5']['count'][$keys[0]] = $v['count'];
							$this->data['last5']['refused'][$keys[0]] = $v['refused'];
							$this->data['last5']['lastactivity'][$keys[0]] = $v['lastactivity'];
						}
					}
				}
				
				// Get top 5 IPs by count
				if(count($this->data['top5']['ip']) < 5){// First we fill up top5 array
					$this->data['top5']['ip'][] = $k;
					$this->data['top5']['count'][] = $v['count'];
					$this->data['top5']['refused'][] = $v['refused'];
					$this->data['top5']['lastactivity'][] = $v['lastactivity'];
				} else{// Then we update with IPs that have more counts
					$keys = array_keys($this->data['top5']['count'],min($this->data['top5']['count']));
					if(count($keys) > 0){
						if($this->data['top5']['count'][$keys[0]] < $v['count']){
							$this->data['top5']['ip'][$keys[0]] = $k;
							$this->data['top5']['count'][$keys[0]] = $v['count'];
							$this->data['top5']['refused'][$keys[0]] = $v['refused'];
							$this->data['top5']['lastactivity'][$keys[0]] = $v['lastactivity'];
						}
					}
				}
			}
			
			// Sort top 5 array
			array_multisort($this->data['top5']['count'], SORT_DESC, $this->data['top5']['ip'], $this->data['top5']['lastactivity'], $this->data['top5']['refused']);
			
			// Sort last 5 array
			array_multisort($this->data['last5']['lastactivity'], SORT_DESC, $this->data['last5']['ip'], $this->data['last5']['count'], $this->data['last5']['refused']);
		}
	}
	
	/**
	 * Echo statistics
	 */
	public function output(){
		if(count($this->ipInfo) > 0){
			echo "\n";
			echo "Total suspicious IP address count: ".count($this->ipInfo)."\n";
			echo "Blacklisted IP address count: ".$this->data['blacklisted_ip_count']."\n";
			echo "\n";
			echo "Top 5 most active IP addresses:\n";
			$countPadLength = strlen($this->data['top5']['count'][0]);
			if($countPadLength < 5) $countPadLength = 5;
			$refusedPadLength = 7;
			foreach($this->data['top5']['refused'] as &$refusedCount){
				if(strlen($refusedCount) > $refusedPadLength) $refusedPadLength = strlen($refusedCount);
			}
			echo "-------------------".str_repeat("-", $countPadLength).str_repeat("-", $refusedPadLength)."--------------------------\n";
			echo "       IP        | ".str_pad("Count",$countPadLength," ",STR_PAD_BOTH)." | ".str_pad("Refused",$refusedPadLength," ",STR_PAD_BOTH)." |   Last activity\n";
			echo "-------------------".str_repeat("-", $countPadLength).str_repeat("-", $refusedPadLength)."--------------------------\n";
			foreach($this->data['top5']['ip'] as $k => $v){
				echo " ".str_pad($v,15," ")." | ".str_pad($this->data['top5']['count'][$k],$countPadLength," ",STR_PAD_BOTH)." | ".str_pad($this->data['top5']['refused'][$k],$refusedPadLength," ",STR_PAD_BOTH)." | ".date("d.m.Y H:i:s", $this->data['top5']['lastactivity'][$k])."\n";
			}
			echo "-------------------".str_repeat("-", $countPadLength).str_repeat("-", $refusedPadLength)."--------------------------\n";
			echo "\n";
			echo "Last activity:\n";
			$countPadLength = strlen($this->data['last5']['count'][0]);
			if($countPadLength < 5) $countPadLength = 5;
			$refusedPadLength = 7;
			foreach($this->data['last5']['refused'] as &$refusedCount){
				if(strlen($refusedCount) > $refusedPadLength) $refusedPadLength = strlen($refusedCount);
			}
			echo "-------------------".str_repeat("-", $countPadLength).str_repeat("-", $refusedPadLength)."--------------------------\n";
			echo "       IP        | ".str_pad("Count",$countPadLength," ",STR_PAD_BOTH)." | ".str_pad("Refused",$refusedPadLength," ",STR_PAD_BOTH)." |   Last activity\n";
			echo "-------------------".str_repeat("-", $countPadLength).str_repeat("-", $refusedPadLength)."--------------------------\n";
			foreach($this->data['last5']['ip'] as $k => $v){
				echo " ".str_pad($v,15," ")." | ".str_pad($this->data['last5']['count'][$k],$countPadLength," ",STR_PAD_BOTH)." | ".str_pad($this->data['last5']['refused'][$k],$refusedPadLength," ",STR_PAD_BOTH)." | ".date("d.m.Y H:i:s", $this->data['last5']['lastactivity'][$k])."\n";
			}
			echo "-------------------".str_repeat("-", $countPadLength).str_repeat("-", $refusedPadLength)."--------------------------\n";
			echo "\n";
		} else{
			echo "No data!\n";
		}
	}
	
	/**
	 * Echo all blacklisted IPs
	 */
	public function outputBlacklist($count = false, $time = false){
		$currentTime = time();
		if(count($this->ipInfo) > 0){
			// Find max count value
			$maxCount = 0;
			$maxRefused = 0;
			foreach($this->ipInfo as &$ip){
				if($ip['count'] > $maxCount) $maxCount = $ip['count'];
				if(isset($ip['refused']) && $ip['refused'] > $maxRefused) $maxRefused = $ip['refused'];
			}
			$countPadLength = strlen($maxCount);
			$refusedPadLength = strlen($maxRefused);
			// Loop through all suspicious IPs
			foreach($this->ipInfo as $k => $v){
				if($v['count'] >= $this->suspiciousEntryMatchCount && (($currentTime - $v['lastactivity']) <= $this->blacklistTime || $this->blacklistTime == 0) && !in_array($k,$this->exclude)){
					echo "a ";
					if(in_array($k,$this->include)){
						$this->log->write("IP address ".$k." is blacklisted by hostblock and is also included in permanent blacklist! Consider removing duplicate from permanent blacklist!");
						continue;
					}
					echo str_pad($k,15);
					if($count == true){
						echo " ".str_pad($v['count'],$countPadLength," ");
						if(isset($v['refused'])) echo " ".str_pad($v['refused'],$refusedPadLength," ");
						else echo " ".str_pad("0",$refusedPadLength," ");
					}
					if($time == true){
						echo " ".date("d.m.Y H:i:s", $v['lastactivity']);
					}
					echo "\n";
				}
			}
			foreach($this->include as &$ip){
				echo "m ";
				echo str_pad($ip,15);
				if($count == true){
					if(isset($this->ipInfo[$ip])){
						echo " ".str_pad($this->ipInfo[$ip]['count'],$countPadLength," ");
						if(isset($this->ipInfo[$ip]['refused'])) echo " ".str_pad($this->ipInfo[$ip]['refused'],$refusedPadLength," ");
						else echo " ".str_pad("0",$refusedPadLength," ");
					} else{
						echo " ".str_pad("0",$countPadLength," ");
						echo " ".str_pad("0",$refusedPadLength," ");
					}
				}
				if($time == true){
					if(isset($this->ipInfo[$ip])){
						echo " ".date("d.m.Y H:i:s", $this->ipInfo[$ip]['lastactivity']);
					} else{
						echo "                    ";
					}
				}
				echo "\n";
			}
		} else{
			echo "No data!\n";
		}
	}
	
	/**
	 * Get blacklisted IPs
	 * @return array
	 */
	public function getBlacklistedIps(){
		$currentTime = time();
		$result = array();
		if(count($this->ipInfo) > 0){
			foreach($this->ipInfo as $k => $v){
				if($v['count'] >= $this->suspiciousEntryMatchCount && (($currentTime - $v['lastactivity']) <= $this->blacklistTime || $this->blacklistTime == 0) && !in_array($k,$this->exclude)){
					if(in_array($k,$this->include)){
						$this->log->write("IP address ".$k." is blacklisted by hostblock and is also included in permanent blacklist! Consider removing duplicate from permanent blacklist!");
						continue;
					}
					$result[] = $k;
				}
			}
			foreach($this->include as $ip){
				$result[] = $ip;
			}
		}
		return $result;
	}
	
	/**
	 * Get blacklisted IP count
	 * @return number
	 */
	public function getBlacklistedIpCount(){
		$currentTime = time();
		$count = count($this->include);
		if(count($this->ipInfo) > 0){
			foreach($this->ipInfo as $k => $v){
				if($v['count'] >= $this->suspiciousEntryMatchCount && (($currentTime - $v['lastactivity']) <= $this->blacklistTime || $this->blacklistTime == 0) && !in_array($k,$this->exclude)){
					if(in_array($k,$this->include)){
						$this->log->write("IP address ".$k." is blacklisted by hostblock and is also included in permanent blacklist! Consider removing duplicate from permanent blacklist!");
						continue;
					}
					$count++;
				}
			}
		}
		return $count;
	}
	
	/**
	 * Get total refused connect count
	 * @return number
	 */
	public function getTotalRefusedConnectCount(){
		$count = 0;
		if(count($this->ipInfo) > 0){
			foreach($this->ipInfo as $ip){
				if(isset($ip['refused'])){
					$count += $ip['refused'];
				}
			}
		}
		return $count;
	}
}
?>