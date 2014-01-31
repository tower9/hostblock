<?php
class AccessUpdate{
	// Log object to write some info in log files
	public $log = null;
	
	/**
	 * Update Apache access file with "Deny from" entries
	 * @param string $path
	 * @param array $blacklistedIps
	 */
	public function updateApacheAccessFile(&$path, &$blacklistedIps){
		$newContents = "";
		$alreadyInFile = array();
		// Open file
		$f = @fopen($path,"r");
		if($f){
			// Check which lines we need to keep and which ones we need to remove
			while(!feof($f)){
				// Read line
				$line = fgets($f,4096);
				// We are interested only in lines that contain "Deny from"
				if(preg_match("/Deny from/", $line)){
					// Trim whitespaces
					$line = trim($line);
					// Split by space or whitespace
					$parts = preg_split("/\s+/", $line);
					foreach($parts as &$part){
						if(ip2long($part) !== false){
							// Check if ip that is written in access file is in blacklist
							if(in_array($part, $blacklistedIps)){
								$newContents .= $line."\n";
								$alreadyInFile[] = $part;
							}
						}
					}
				} else{
					$newContents .= $line;
				}
				// Slepp for 1 microsecond (so that we don't take all CPU resources and leave small part for other processes
				usleep(1);
			}
			// Append with new "Deny from" entries
			foreach($blacklistedIps as &$blacklistedIp){
				if(!in_array($blacklistedIp,$alreadyInFile)){
					$newContents .= "Deny from ".$blacklistedIp."\n";
				}
			}
			// Close file
			@fclose($f);
			// Writing new contents to file
			file_put_contents($path, $newContents);
		}
	}
	
	/**
	 * Update hosts.deny file with "sshd: " entries
	 * @param string $path
	 * @param array $blacklistedIps
	 */
	public function updateHostsDenyFile(&$path, &$blacklistedIps){
		$newContents = "";
		$alreadyInFile = array();
		// Open file
		$f = @fopen($path,"r");
		if($f){
			// Check which lines we need to keep and which ones we need to remove
			while(!feof($f)){
				// Read line
				$line = fgets($f,4096);
				// We are interested only in lines that contain "sshd"
				if(preg_match("/sshd/", $line)){
					// Trim whitespaces
					$line = trim($line);
					// Split by space or whitespace
					$parts = preg_split("/\s+/", $line);
					foreach($parts as &$part){
						if(ip2long($part) !== false){
							// If ip that is written in access file is in blacklist
							if(in_array($part, $blacklistedIps)){
								$newContents .= $line."\n";
								$alreadyInFile[] = $part;
							}
						}
					}
				} else{
					$newContents .= $line;
				}
				// Slepp for 1 microsecond (so that we don't take all CPU resources and leave small part for other processes
				usleep(1);
			}
			// Append with new "Deny from" entries
			foreach($blacklistedIps as &$blacklistedIp){
				if(!in_array($blacklistedIp,$alreadyInFile)){
					$newContents .= "sshd: ".$blacklistedIp."\n";
				}
			}
			// Close file
			@fclose($f);
			// Writing new contents to file
			file_put_contents($path, $newContents);
		}
	}
}
?>