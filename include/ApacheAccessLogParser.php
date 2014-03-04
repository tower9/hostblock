<?php
/**
 * Apache access_log file parser.
 * 
 * @author Rolands Kusiņš
 * @license GPL
 *
 */
class ApacheAccessLogParser{
	// Regex patterns for log file format
	private $patterns = array(
		'%h' => '(?P<ip>\S+)',// IP address of client
		'%l' => '(?P<identity>\S+)',// Identity of user determined by identd
		'%u' => '(?P<username>\S+)',// User name determined by HTTP authentication
		'%t' => '(?P<datetime>\S+:\d+:\d+:\d+ \+\S+)',// Time the server finished processing request (17/Jan/2014:04:12:06 +0000)
		'%r' => '(?P<request>(\s*\S+\s*)|(\s*\S+\s*\S+\s*)|(\s*\S+\s*\S+\s*\S+\s*))',// Request from client ("GET / HTTP/1.1")
		'%s' => '(?P<statuscode>\S+)',// HTTP status code sent from server to client (200, 400, 403, etc)
		'%b' => '(?P<size>\S+)',// Size of response sent to client in bytes
		'%v' => '(?P<referer>\S+)',// Referer, page that sent to this URL
		'%i' => '(?P<agent>.*?)',// User agent identification string
	);
	// File format
	private $format = "%h %l %u \[%t\] \"%r\" %s %b";
	// Object for log file writing
	public $log = null;
	// Suspicious patterns
	public $suspiciousPatterns = array();
	// Parsed line data
	private $data = array();
	
	/**
	 * Check Apache access log file for new entries and match against patterns
	 * 
	 * @param array $apacheAccessLogFile with information about Apache access log file (path, offset, format)
	 * @param array $ipInfo with information about suspicious IP addresses
	 * @param boolean $updateHostData will be updated to true if $ipInfo is updated
	 * @param boolean $updateOffsets will be updated to true if new lines were parsed
	 * @return integer with suspicious activity pattern match count
	 */
	public function parseFile(&$apacheAccessLogFile, &$ipInfo, &$updateHostData, &$updateOffsets){
		$newMatchCount = 0;
		// Reset offset if file size has reduced (truncated)
		$fileSize = filesize($apacheAccessLogFile['path']);
		if($fileSize < $apacheAccessLogFile['offset']){
			$apacheAccessLogFile['offset'] = 0;
		}
		// Open apache access log file for reading
		$f = @fopen($apacheAccessLogFile['path'],"r");
		if($f){
			// Seek to last position we know
			fseek($f, $apacheAccessLogFile['offset']);
			// Read new lines until end of file
			while(!feof($f)){
				// Read line
				$line = @fgets($f,4096);
				if($line !== false){
					$line = trim($line);
					// Update parser with current file line format
					if(isset($apacheAccessLogFile['format'])) $this->format = $apacheAccessLogFile['format'];
					// If we are able to parse a line
					if($this->parseLine($line) == true){
						// If we match suspicious pattern
						if($this->matchSuspiciousPatterns() == true){
							// Init count for ip if it is first time we see it
							if(!isset($ipInfo[$this->data['ip']])) $ipInfo[$this->data['ip']] = array(
									'count' => 0,
							);
							// Increase pattern match count
							$ipInfo[$this->data['ip']]['count']++;
							// Try parsing time of request
							$time = strtotime($this->data['datetime']);
							if($time != false && (!isset($ipInfo[$this->data['ip']]['lastactivity']) || $ipInfo[$this->data['ip']]['lastactivity'] < $time)) $ipInfo[$this->data['ip']]['lastactivity'] = $time;
							// We need to update host data, because we changed IP match count
							$updateHostData = true;
							// We found new match against pattern
							$newMatchCount++;
						}
					} else{
						// Output filename and line that we were unable to parse, this might later be unnecesarry spam, but for development&testing it helps
						$this->log->write("Unable to parse line! ".$apacheAccessLogFile['path'].": ".$line,"error");
					}
				}
				// Slepp for 10 microseconds (so that we don't take all CPU resources and leave small part to other processes
				usleep(10);
			}
			// Get current offset
			$currentOffset = ftell($f);
			if($apacheAccessLogFile['offset'] != $currentOffset){
				// Update current offset for file
				$apacheAccessLogFile['offset'] = $currentOffset;
				// Because offset has changed, we need to update file data
				$updateOffsets = true;
			}
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
		// Get keys of patterns
		$tmp = array_keys($this->patterns);
		// Replace format identifiers with regexp patterns to create pattern for whole line
		$formatPattern = str_replace($tmp, $this->patterns, $this->format);
		// Escape quotes in pattern
		$formatPattern = str_replace("\"", "\\\"", $formatPattern);
		$formatPattern = "/^".$formatPattern."/";
		$data = array();
		// Perform a match on line with format
		preg_match($formatPattern, $line, $data);
		// If match succeeded, then we try to get some data
		if(count($data) > 0){
			if(isset($data['ip'])) $this->data['ip'] = $data['ip'];
			if(isset($data['identity'])) $this->data['identity'] = $data['identity'];
			if(isset($data['username'])) $this->data['username'] = $data['username'];
			if(isset($data['datetime'])) $this->data['datetime'] = $data['datetime'];
			if(isset($data['request'])) $this->data['request'] = $data['request'];
			if(isset($data['statuscode'])) $this->data['statuscode'] = $data['statuscode'];
			if(isset($data['size'])) $this->data['size'] = $data['size'];
			if(isset($data['referer'])) $this->data['referer'] = $data['referer'];
			if(isset($data['agent'])) $this->data['agent'] = $data['agent'];
		}
		
		if(count($this->data) > 0) return true;
		else return false;
	}
	
	/**
	 * Match patterns against request to find suspicious activities
	 * 
	 * @return boolean
	 */
	private function matchSuspiciousPatterns(){
		foreach($this->suspiciousPatterns as &$pattern){
			if(isset($this->data['request'])){
				if(preg_match($pattern, $this->data['request'])){
					return true;
				}
			}
		}
		return false;
	}
}
?>