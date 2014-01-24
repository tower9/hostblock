<?php
class SshdLogParser{
	// Regex patterns for log file format
	private $patterns = array(
		'%i' => '(?P<ip>\d+\.\d+\.\d+\.\d+)',// IP address of client
		'%u' => '(?P<username>\S+)',// User name
		'%d' => '(?P<datetime>\S+ \d+ \d+:\d+:\d+)',// Date time
		'%h' => '(?P<hostname>\S+)',// Hostname of server
		'%p' => '(?P<pid>\d+)',// Process PID
	);
	// Object for log file writing
	public $log = null;
	// Entry format
	public $formats = array(
		"%d %h sshd\[%p\]: Invalid user %u from %i",
	);
	// Parsed line data
	private $data = array();
	
	/**
	 * Parse SSHd log file
	 * 
	 * @param array $sshdLogFile
	 * @param array $ipInfo
	 * @param boolean $updateHostData
	 * @param boolean $updateOffsets
	 * @param string $year
	 * @return number
	 */
	public function parseFile(&$sshdLogFile, &$ipInfo, &$updateHostData, &$updateOffsets, $year=null){
		$newMatchCount = 0;
		if(is_null($year)) $year = date("Y");
		// Reset offset if file size has reduced (truncated)
		$fileSize = filesize($sshdLogFile['path']);
		if($fileSize < $sshdLogFile['offset']){
			$sshdLogFile['offset'] = 0;
		}
		// Open log file for reading
		$f = @fopen($sshdLogFile['path'],"r");
		if($f){
			// Seek to last position we know
			fseek($f, $sshdLogFile['offset']);
			// Read new lines until end of file
			while(!feof($f)){
				// Read line
				$line = @fgets($f,4096);
				if($line !== false){
					$line = trim($line);
					// We check only lines with "sshd"
					if(preg_match("/sshd/", $line)){
						// If we are able to parse a line and it matches "Invalid user"
						if($this->parseLine($line) == true){
							// Init count for ip if it is first time we see it
							if(!isset($ipInfo[$this->data['ip']])) $ipInfo[$this->data['ip']] = array(
									'count' => 0,
							);
							// Increase pattern match count
							$ipInfo[$this->data['ip']]['count']++;
							// Try parsing time of request
							$datetime = substr($this->data['datetime'],0,3)."-".substr($this->data['datetime'],4,2)."-".$year.substr($this->data['datetime'],7);
							$time = strtotime($datetime);
							if($time != false && (!isset($ipInfo[$this->data['ip']]['lastactivity']) || $ipInfo[$this->data['ip']]['lastactivity'] < $time)) $ipInfo[$this->data['ip']]['lastactivity'] = $time;
							// We need to update host data, because we changed IP match count
							$updateHostData = true;
							// We found new match against pattern
							$newMatchCount++;
						}
					}
				}
				// Slepp for 1 microsecond (so that we don't take all CPU resources and leave small part for other processes
				usleep(1);
			}
			// Get current offset
			$currentOffset = ftell($f);
			if($sshdLogFile['offset'] != $currentOffset){
				// Update current offset for file
				$sshdLogFile['offset'] = $currentOffset;
				// Because offset has changed, we need to update file data
				$updateOffsets = true;
			}
			// Close file
			@fclose($f);
		}
		
		return $newMatchCount;
	}
	
	/**
	 * Parse single line
	 * 
	 * @param string $line
	 * @return boolean
	 */
	private function parseLine($line){
		// Init data
		$this->data = array();
		foreach($this->formats as &$format){
			// Get keys of patterns
			$tmp = array_keys($this->patterns);
			// Replace format identifiers with regexp patterns to create pattern for whole line
			$formatPattern = str_replace($tmp, $this->patterns, $format);
			// Escape quotes in pattern
			$formatPattern = str_replace("\"", "\\\"", $formatPattern);
			$formatPattern = "/^".$formatPattern."/";
			$data = array();
			// Perform a match on line with format
			preg_match($formatPattern, $line, $data);
			// If match succeeded, then we try to get some data
			if(count($data) > 0){
				if(isset($data['ip'])) $this->data['ip'] = $data['ip'];
				if(isset($data['username'])) $this->data['username'] = $data['username'];
				if(isset($data['datetime'])) $this->data['datetime'] = $data['datetime'];
				if(isset($data['hostname'])) $this->data['hostname'] = $data['hostname'];
				if(isset($data['pid'])) $this->data['pid'] = $data['pid'];
			}
			if(count($this->data) > 0) return true;
		}
		
		return false;
	}
}
?>