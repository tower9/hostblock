<?php
class Log{
	// Array with file handlers that are currently open, we keep the files open while this class is used
	public $files = array();
	public $logDirectory = "/var/log";
	
	/**
	 * On destruct we close all open file handlers
	 */
	public function __destruct(){
		foreach($this->files as &$file){
			@fclose($file);
		}
	}
	
	/**
	 * Write to log file
	 * @param string $message
	 * @param string $log
	 */
	public function write($message, $log="main"){
		// Check if file is open
		if(!isset($this->files[$log]) || !$this->files[$log]){
			if($log == "main"){
				$this->files["main"] = @fopen($this->logDirectory."/hostblock.log", "a");
			} else{
				$this->files[$log] = @fopen($this->logDirectory."/hostblock-".$log.".log", "a");
			}
		}
		// Write to log file
		if($this->files[$log]){
			@fwrite($this->files[$log],"[".date("d.m.Y H:i:s")."] ".$message."\n");
		}
	}
}
?>