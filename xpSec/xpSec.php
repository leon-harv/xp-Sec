<?php

//CONFIGURATION// 

	$warningFile = "/warnings.txt";
	//LOCATION OF WARNINGS/BAN FILE.

	$maxTempBan = 5;				
	//MAXIMUM BANS BEFORE PERMANENT IP BAN.

	$URLkeywords = array('">', "<script", "alert(", "<iframe", "src=", ".js", "document.location", "window.location", "javascript:", "onload", "onmouseover");
	//KEYWORDS TO DETECT ANYWHERE IN URLS ~ case-insensitive.

	$POSTkeywords = array('">', "<script", "alert(", "<iframe", "src=", ".js", "document.location", "window.location", "javascript:", "onload", "onmouseover");
	//KEYWORDS TO DETECT IN POST REQUESTS ~ case-insensitive.

	$GETkeywords = array("union select", "order by", "'", "table_schema", "select count", "group by", "../", "/etc/");
	//KEYWORDS TO DETECT IN GET REQUESTS ~ case-insensitive.

	$banTime = 30; 
	//TIME FOR TEMPORARY BAN IN MINUTES ~ WHICH IS THEN MULTIPLIED BY THE AMOUNT OF BANS/DETECTIONS A PERSON HAS HAD.

	$banChance = 0;
	//DETECTION CHANCES BEFORE FIRST TEMPORARY BAN.

	$errorPage = "/error.html";
	//ERROR PAGE TO DISPLAY ON BROWSERS THAT AREN'T CHROME.

	$chromeError = 0;
	//If 1, chrome will display this http://puu.sh/6k7zS.png if banned. NOTE: this can be spoofed on another browser 
	//and can allow for full path disclosure.

	$GETpreventXSS = 1;
	//If 1, all GET requests will be sanatized using htmlentities().

	$POSTpreventXSS = 1;
	//If 1, all POST requests will be sanatized using htmlentities().

//CONFIGURATION// 


//BAN CHECK//
$IP = $_SERVER['REMOTE_ADDR'];
$lines = file(realpath(dirname(__FILE__)) . $warningFile, FILE_IGNORE_NEW_LINES);
$banCount = 0;
$banStatus = 0;

foreach($lines as $key) {
	$keyParse = explode("~", $key);
	if ($IP == $keyParse[0]) {
		$banTime = time() - ($banTime * 60) * $banCount;
		if ($keyParse[1] > $banTime && $banCount >= $banChance) {
			$banStatus = 1;
		}
		$banCount++;
	}
}
if ($banStatus == 1 || $banCount > $maxTempBan) {
	killPage();
} 
//BAN CHECK//




////DETECTION METHODS//// ~ Add your own here, just be sure to call addWarning() then killPage() once a detection occurs.


//URL KEYWORD CHECK//
if (isset($_SERVER['REQUEST_URI'])) {
	$url = urldecode($_SERVER['REQUEST_URI']);
	foreach($URLkeywords as $key) {
		if (stripos($url, $key) !== FALSE) {
			addWarning();
			killPage();
		} 
	}
}
//URL KEYWORD CHECK//




//POST REQUEST CHECK//
foreach($_POST as $postName => $postData) {
	foreach($POSTkeywords as $key) {
		if (stripos($postData, $key) !== FALSE) {
			addWarning();
			killPage();
		} 
	}
	if ($POSTpreventXSS = 1) {
		$_POST[$postName] = htmlentities($_POST[$postName]); //XSS prevention
	}
}
//POST REQUEST CHECK//




//GET REQUEST CHECK//
foreach($_GET as $getName => $getData) {

	//RFI CHECK//
	$_GET[$getName] = str_replace(chr(0), '', $_GET[$getName]); //NULL BYTE PREVENTION
	$getData = str_replace(chr(0), '', $getData); //NULL BYTE PREVENTION

	if (filter_var($getData, FILTER_VALIDATE_URL) == TRUE) {
		addWarning();
		killPage();
	} 
	//RFI CHECK//

	//GET REQUEST KEYWORD CHECK//
	foreach($GETkeywords as $key) {
		if (stripos($getData, $key) !== FALSE) {
			addWarning();
			killPage();
		} 
	}
	//GET REQUEST KEYWORD CHECK//
	if ($GETpreventXSS = 1) {
		$_GET[$getName] = htmlentities($_GET[$getName]); //XSS prevention
	}
}
//GET REQUEST CHECK//




//CSRF PROTECTION//
if (is_array($_POST)) {
    if (isset($_SERVER["HTTP_ORIGIN"])) {
        $correctAddress = "http://" . $_SERVER["SERVER_NAME"];
        if (stripos($correctAddress, $_SERVER["HTTP_ORIGIN"]) !== 0) {
			addWarning();
			killPage();
        } 
    }
}
//CSRF PROTECTION//


////DETECTION METHODS////



////FUNCTIONS////
function killPage() { 
	global $errorPage, $chromeError;
	if (stripos($_SERVER['HTTP_USER_AGENT'], "chrome") && $chromeError == 1) {
		while (1) { 
			echo ' ';
		}
	} else {
		 header('HTTP/1.1 500 Internal Server Error', true, 500);
		 include realpath(dirname(__FILE__)) . $errorPage;
		 die();
	}
}

function addWarning() {
	global $warningFile, $IP;
	$data = $IP . "~" . time() . "\r\n";
	file_put_contents(realpath(dirname(__FILE__)) . $warningFile, $data, FILE_APPEND);
}
////FUNCTIONS////
?>