<?php
/**
 * Log writing class
 * 
 * @author Rolands Kusiņš
 * @license GPL
 *
 */
class Log{
	// Array with file handlers that are currently open, we keep the files open while this class is used
	private $files = array();
	// Directory where to write log files
	public $logDirectory = "/var/log";
	// Datetime format
	public $dateTimeFormat = "Y-m-d H:i:s";
	
	/**
	 * Destruct
	 */
	public function __destruct(){
		// Close all open files
		foreach($this->files as &$file){
			@fclose($file);
		}
	}
	
	/**
	 * Write to log file
	 * 
	 * @param string $message is text to write in log file
	 * @param string $log optional, log file will be called hostblock.log, if this argumet is passed, then log file will be called hosblock-[$log].log
	 */
	public function write($message, $log="main"){
		// If file is not open
		if(!isset($this->files[$log]) || !$this->files[$log]){
			if($log == "main"){
				$this->files["main"] = @fopen($this->logDirectory."/hostblock.log", "a");
			} else{
				$this->files[$log] = @fopen($this->logDirectory."/hostblock-".$log.".log", "a");
			}
		}
		// Write to log file
		if($this->files[$log]){
			@fwrite($this->files[$log],"[".date($this->dateTimeFormat)."] ".$message."\n");
		}
	}
}
?>