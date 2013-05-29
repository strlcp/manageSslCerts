<?php
ini_set('error_reporting', E_ALL);

/*
* 
* Copyright: strlcp@gmx.de
* do not use in context of:
* -government/military issues
* -human discrimination
* -doing sencless harm to animals
*/


/*
*  defines
*/
define('AP_DIR', '/var/ssl.crt/www');
define("SSL_CONF", AP_DIR . "/conf/openssl.cnf");
define("CA_DIR", AP_DIR . "/ca/");    
define ("USR_DIR", AP_DIR . "/usr/");

define("ROOT_CA", AP_DIR . "/ca/main-ca.pem");
define("WEB_DIR", "/var/www/htdocs/ssl"); 
/*
*
*/

/***************************************************************************************************/
/***************************************************************************************************/
/*
*	member class holding all member specific methods
*/
/***************************************************************************************************/
/***************************************************************************************************/

abstract class orCerM extends orgCerts {



	public $storeKeys = TRUE; // got to change this  

/***************************************************************************************************/
// member functions
/***************************************************************************************************/



// sucks as public but password/keyfile and resricted access in __construct is to much 
/***************************************************************************************************/
/*
* log in the system, load ca and private key to gen certs. dn defaults loaded from the ca later.
*		error checking should be done ! // parse sslerrorstringa
*		setting this->ca andi this->caK form files to resources 	
* 		return array(ca, privatekey); as resources (is that usefull?)
*/
/***************************************************************************************************/
	public function ckCa($pass, $keyfile = False) {
// load ca
		$file = $this->ca; // could e a rstricted one
		if (! file_exists($file)) return "ERR: file not found caFile " . $file;
		$ca = openssl_x509_read(file_get_contents($file));
//	ca loaded 
// 	load key
		if ($keyfile == null) $keyfile = $this->caK; // could e a rstricted one
		if (! file_exists($keyfile)) return "ERR: file not found  privateKeyFile" . $keyfile;
		$priv = openssl_pkey_get_private("file://" . $keyfile, $pass);
// key loaded errors could be check ???
//		print openssl_error_string() . "\n";	
// changing value of ca/caK from filename to resource	
		$this->ca = $ca;
		$this->caK = $priv;
		return array($ca, $priv);
	}
/***************************************************************************************************/


/***************************************************************************************************/
/*
*	setting config values given by $args = array(key => value) 
*/
/***************************************************************************************************/
	public function setConfig(&$args) {
		$replaced = array_replace($this->config, $args); 
		if ($replaced) $this->config = $replaced; 		
	}

/***************************************************************************************************/




/***************************************************************************************************/
/*
*	generating a key pair 
*	storing p_key in file if file arg given
*	returning array(priv => pkey, pub => pubkey)   
*	neeed pem encoded keys for csr - so its senceless to return a resource 
*/	
/***************************************************************************************************/
	private function genKeys($config = FALSE) {
		if ($config == null) $config = $this->config;
		$res = openssl_pkey_new($config); // the private/public key pair.
		openssl_pkey_export($res, $p_key);  // export pivate
		$pubkey = openssl_pkey_get_details($res); // get infos about key
		return array("private" => $p_key, "public" => $pubkey["key"]);
	}
/***************************************************************************************************/



/***************************************************************************************************/
/*
*	config values like chiper and so may be changed on other palce
*	needs certification request and v3_extensions corresponding to cnf file	
*	return $cert (singed by this->ca)
*	append cert in db and index increasing  serial	
*/	
/***************************************************************************************************/
	private function signcert($csr, $v3_ext) {
		$config = $this->config;
		$config["x509_extensions"] = $v3_ext;

		if (!isset ($days)) { $days = $this->days; } 	// change her for a cong value user depend
		$serial = $this->caS; 
		$sR = getSerial($serial);
		$cert = openssl_csr_sign($csr, $this->ca, $this->caK, $days, $config, $sR); // x509 cert 
//		print var_dump (openssl_error_string());
//	apppend to index 
		$fh = fopen($this->caI, "a+");
		fputs($fh, "V \t " . timeZulu($days) . "\t unkwon \t" . $sR . "\t" . $this->getDnName($this->ca) . "\n"); 
		fclose($fh);
//	apppend to db 
		openssl_x509_export_to_file($cert, $this->caDb . "/" . $sR .".pem");	
		return $cert;	
	}
/***************************************************************************************************/



/***************************************************************************************************/
/*
*	needs key dn and config
*	returns a requset
*/
/***************************************************************************************************/
	private function makeRequest($key, &$dn, $config) {
		$csr = openssl_csr_new($dn, $key, $config); // x509 csr a
		return $csr;			
	}
/***************************************************************************************************/





/***************************************************************************************************/
/*
*	checks wether name is used for a certificate or key bevor.
*	keys should be placed offline	!!!
*	throws Execption
*/
/***************************************************************************************************/
	protected function ckCert($str) {
		if (file_exists($this->certDir . $str. ".pem")) {
			throw new InvalidArgumentException("cert found for [str=$str]");
		}
		if (file_exists($this->keyDir . $str. ".pem")) {
			throw new InvalidArgumentException("private key found for [str=$str]");
		}
	}
/***************************************************************************************************/


/***************************************************************************************************/
/*
*	checks wether name is used for a ca bevor.
*	throws Execption
*/
/***************************************************************************************************/
	protected function ckCaDir($str) {
		if (file_exists($str)) {
			throw new InvalidArgumentException("ca Dir found for [str=$str]");
		}
	}
/***************************************************************************************************/


/***************************************************************************************************/
/*
*	creating a cert with name string and private key password pass
*	returning pem encoded key as string and the cert as php resource
*/
/***************************************************************************************************/
	public function crCrt($string, $pass, $dir=FALSE) {
		$type = "usr_cert";	
		if ($dir == null) $dir = $this->certDir; 
		$placeCert = $dir . "/" . $string . ".pem";	
		$this->ckCert($string);
		list ($cryptK, $cert) = $this->cAsC($string, $type, $pass);	
		$this->svCert($cert, $placeCert);
		if ($this->storeKeys) {
			$placeKey = $this->keyDir . "/" . $string . ".pem";
			$this->svKey($cryptK, $placeKey, $pass); 
		}
		return array($cryptK, $cert);
	}
/***************************************************************************************************/


/***************************************************************************************************/
/*
*	creating a ca with name string and private key password pass
*	returning pem encoded key as string and the cert as php resource
*/
/***************************************************************************************************/
	public function crRole($string, $pass) {
		$type = "v3_ca";		
		$certDir = $this->restrictedDir . "/" .  $string;
		$this->ckCaDir($certDir);	
		list ($cryptK, $cert) = $this->cAsC($string, $type, $pass);	
		$this->createCaFolders($certDir);
		$placeCert = $certDir . "/ca/ca.pem";	
		$this->svCert($cert, $placeCert);
		if ($this->storeKeys) {
			$placeKey = $certDir . "/ca/key.pem";
			$this->svKey($cryptK, $placeKey, $pass); 
		}
		return array($cryptK, $cert);
	}
/***************************************************************************************************/


/***************************************************************************************************/
/*	
*	craeting files and folders that are usefull for a ca
*/
/***************************************************************************************************/
	protected function createCaFolders ($topDir) {
		foreach (array ("ca", "ca/ca.db", "certs", "keys") as $folder) {  
			mkdir($topDir . "/" . $folder, 0700, true);
		}	 
		$fh = fopen($topDir . "/ca/serial", "w");
		fputs ($fh, "00");
		fclose($fh);
		$fh = fopen($topDir ."/ca/index", "w");
		fputs ($fh, "");
		fclose($fh);
	} 
/***************************************************************************************************/


/***************************************************************************************************/
/*
*	storing the cert
*/
/***************************************************************************************************/
	function svCert($cert, $place) {
		openssl_x509_export_to_file($cert, $place);	
	}
/***************************************************************************************************/


/***************************************************************************************************/
/*
*	storing the key
*/
/***************************************************************************************************/
	function svKey($key, $place, $pass) {
		openssl_pkey_export_to_file($key, $place, $pass);
	}
/***************************************************************************************************/



/***************************************************************************************************/
/***************************************************************************************************/
/*
*	main certifiaction routine
*	calls 	genKeys(); 
*		makeRequest(key, dn, config)
*		singCert(request, type)		
*	makes the SAN stuff	
*/
/***************************************************************************************************/
/***************************************************************************************************/
	private function cAsC($string, $type, $pass) {
// got to change because of leck of flexibility

		$dn = $this->getDnSub();
	// var_dump($dn = $this->getDnSub());

/* 
as far as I know 
/// SAN got :

    *  email:
    * DNS:
    * IP:
    * URI:
    * RID:
    * Microsoft_GUID
    * Microsoft_UPN 

*/

		$SAN = "email:" . $dn["emailAddress"];
//		$SAN .= ",URI:localhost";
		putenv("SAN=$SAN");
		$keys = $this->genKeys();	// not needed to change config here ?
		$csr = $this->makeRequest($keys["private"], $dn, $this->config); 
		$cert = $this->signCert($csr, $type); 
		return array ($keys["private"], $cert); 
	}
/***************************************************************************************************/

}

/***************************************************************************************************/
/***************************************************************************************************/
/*
*	admin class holds all admin spezific methods
*/
/***************************************************************************************************/
/***************************************************************************************************/

class orCerA extends orCerM {

/***************************************************************************************************/
/*
*
*/
/***************************************************************************************************/
	function __construct($restr = FALSE) {
		$this->usrDir = AP_DIR . "usr/"; 
		if ( $restr == null) {	
			$this->ca = CA_DIR . "main-ca.pem";	
			$this->caK = CA_DIR . "main-key.pem"; // otherwise use the cert one
			$this->caS = CA_DIR . "main-serial";
			$this->caDb = CA_DIR . "ca.db";
			$this->caI = CA_DIR . "index";
			$this->certDir = AP_DIR . "/certs/";
			$this->keyDir = AP_DIR . "/keys/";
			$this->restrictedDir = AP_DIR . "/restricted";
		}else {	
			$rt = AP_DIR . "/restricted/" . $restr;
			$this->ca = $rt . "/ca/ca.pem";
			$this->caK = $rt . "/ca/key.pem";
			$this->caS = $rt . "/ca/serial";
			$this->caDb = $rt . "/ca/ca.db";
			$this->caI = $rt . "/ca/index";
			$this->certDir = $rt . "/certs";
			$this->keyDir = $rt . "/keys";
			$this->restrictedDir = "/dev/null";	// 
		}
	
	}
/***************************************************************************************************/

/***************************************************************************************************/
/*
*	set dn values other then found in ca	
*/	
/***************************************************************************************************/
	public function setDn(&$args) {
		$iargs = array_replace($this->dn, $args); 
//		if ($args) $this->dn = $replaced; 		
		if ($args) return; 		
	}
/***************************************************************************************************/



/***************************************************************************************************/
/*
*	creating a new role (maybee user/member  class ?
*	maybee senceless ?
*/	
/***************************************************************************************************/
	public function crUser($user) {
		if (file_exists(USR_DIR .$user)) {
			throw new InvalidArgumentException("already exist[user=$user]");
		}
		$uDir = USR_DIR . $user; 
		mkdir (USR_DIR . $user . "/crypt", 0700, true); 
		mkdir (AP_DIR . "/requests/" . $user, 0700, true); // user puts request on ???
// maybee use create ca with different dn ???	
		$this->createCaFolders($uDir);
		
// create cert to login ?
		$stamp = date("Ymd-His");
		$pass = "adsasds";	
		print $stamp;
		$this->crCrt($stamp, $pass, USR_DIR . $user . "/crypt");
		
		/*
		*/	
		


	}

// will do this some time ...
/***************************************************************************************************/
	public function upRoleCa($role) {

	}
/***************************************************************************************************/
	public function upRoleCert($role) {

	}
/***************************************************************************************************/
/***************************************************************************************************/
}

/***************************************************************************************************/
/***************************************************************************************************/
/***************************************************************************************************/

/***************************************************************************************************/
// the user class
/***************************************************************************************************/
/*
// there is no sence to build the userclass at now !
*/

class orCerU extends orCerM {
	function __construct($role, $restr = FALSE) {

		if (!file_exists(USR_DIR . $role)) {	
			throw new InvalidArgumentException("unknown role for certification management [role=$role]");
		}	

		/*
		$dirs = glob(USR_DIR . "*", GLOB_ONLYDIR);	
		foreach ($dirs as $entry){
			$files[] = basename($entry);
		}  
		if (!in_array($role, $files)){
			throw new InvalidArgumentException("unknown role for certification management [irole=$role]");
		}	
		*/
	}
	public function reqCert($name) {

	}


}
/***************************************************************************************************/
/***************************************************************************************************/
/***************************************************************************************************/

abstract class orgCerts {

/*
*	config
*/
	protected $days = 365; // should be readed from config ?	
	protected $config = array(
		'config' => SSL_CONF,
		'private_key_bits' => 2048, 
		'encrypt_key' => true, 
//		'private_key_type' => 'OPENSSL_KEYTYPE_RSA',
		'digest_algo' => 'sha1',
		'encrypt_key_cipher' => 'OPENSS,L_CIPHER_AES_256_CBC',
		'x509_extensions' => 'v3_ca',
		'req_extensions' => 'v3_req'
	);
// dn is only needed at install 
	protected $dn = array(
    		"countryName" => "AF",
    		"stateOrProvinceName" => "AF-KAN",
    		"localityName" => "Kandahar",
    		"organizationName" => "Home of Skatistan",
    		"organizationalUnitName" => "Skatistan",
    		"commonName" => "Mind opening",
    		"emailAddress" => "chairman@whitehouse.gov"
	);


/***************************************************************************************************/
/*
*	only get Name index file
*/
/***************************************************************************************************/
	function getDnName($cert = FALSE){
		if ($cert == null) {
			$cert = $this->ca;
		}
		$result = openssl_x509_parse($cert, false);
		$sj = $result["subject"];
		$name = "/C=" .$sj["countryName"] .  "/";
		$name .= "ST=" . $sj["stateOrProvinceName"] . "/";
		$name .= "L=" . $sj["localityName"] . "/";
		$name .= "O=" . $sj["organizationName"] ."/";
		$name .= "OU=" .$sj["organizationalUnitName"] . "/";
		$name .= "CN=" . $sj["commonName"] . "/";
		$name .= "emailAddress=" . $sj["emailAddress"]; 
		return $name;
	}
/***************************************************************************************************/

/***************************************************************************************************/
/*
*	only get subject $dn array
*/
/***************************************************************************************************/
	protected function getDnSub($cert = FALSE){
		if ($cert == null) {
			$cert = $this->ca;
		}
		$result = openssl_x509_parse($cert, false);
		return $result["subject"] ;
	}
/***************************************************************************************************/


/***************************************************************************************************/
/*
* 	return a dn arrys, must be improved !	
*/
/***************************************************************************************************/
	public function getDnAll($cert = FALSE){
		if ($cert == null) {
			$cert = $this->ca;
		}
		$result = openssl_x509_parse($cert, false);
		$sj = $result["subject"];
		$name = "/C=" .$sj["countryName"] .  "/";
		$name .= "ST=" . $sj["stateOrProvinceName"] . "/";
		$name .= "L=" . $sj["localityName"] . "/";
		$name .= "O=" . $sj["organizationName"] ."/";
		$name .= "OU=" .$sj["organizationalUnitName"] . "/";
		$name .= "CN=" . $sj["commonName"] . "/";
		$name .= "emailAddress=" . $sj["emailAddress"]; 
		$issuer = $result["issuer"]; 	
		return array($name , $result["subject"], $result["issuer"]) ;
	}

/***************************************************************************************************/
}
/***************************************************************************************************/
/***************************************************************************************************/

/***************************************************************************************************
//	functions :

***************************************************************************************************/

function timeZulu($days=FALSE) {
	date_default_timezone_set('UTC');
	return date("mdyHis", mktime(date("H"), date("i"), date("s"), date("m"), date ("j")+ $days, date("y"))) ."Z";
}
/*
*	reads and writes serial file, returning next serial value filename is the given arg 
*/

function getSerial($file) {
	$fp = fopen($file, "r");
	list($serial) = fscanf($fp, "%x");
	fclose($fp);
	$fp = fopen($file, "w");
	fputs($fp, sprintf("%04X", $serial + 1) . chr(0) . chr(10) );
	fclose($fp);
	return $serial + 1;
	}

/***************************************************************************************************
*
*	here the install class 
*	witch is really bullshit!!!
*
***************************************************************************************************/
class instDir extends orgCerts {
	function __construct($passwd){
		print inl();
		if (file_exists(CA_DIR ."main-ca.pem")) {
			return "ERR: certificate alreday exists in " . CA_DIR;
		}	
		$config = $this->config;
		$dn = $this->dn;
// making keys:
		$res = openssl_pkey_new(); // the private/public key pair.
		$dt = openssl_pkey_get_details($res);
		$priv = openssl_pkey_get_private($res);
		$pub = 	$dt["key"];
		openssl_pkey_export($priv, $pr);
// making cert :
		$SAN = "email:" . $dn["emailAddress"];
		putenv("SAN=$SAN");
		$csr = openssl_csr_new($dn, $pr, $config); // x509 csr 
		$cert = openssl_csr_sign($csr, null, $priv, "365", $this->config); // x509 cert 
// storing cert and  creating files 		
		openssl_x509_export_to_file($cert, CA_DIR . "main-ca.pem");			
		openssl_pkey_export_to_file($priv, CA_DIR . "main-key.pem", $passwd, $this->config);			
		print "generate cert \n \t passwd for keys ist \t  " . $passwd . "\n";
		return "MSG: Cert an key storing done !";
	}
}
/*
*	install the foders (maybe could be done by installing users to ??
*/
function inl () {
	if ( file_exists(AP_DIR . "/ca")) { 
			return "ERR: Installation already found in " . AP_DIR;
	}
	foreach ( array ("conf", "ca", "certs", "keys", "crypto", "user", "restricted") as $pth) {
			$pth = AP_DIR . "/" . $pth;	
			mkdir ($pth, 0700, true);
	}	
// cadir 
	mkdir (CA_DIR . "ca.db", 0700, true);
// serial
	$fh = fopen(CA_DIR . "main-serial", "w");
	fputs ($fh, "00");
	fclose($fh);
	$fh = fopen(CA_DIR ."index", "w");
	fputs ($fh, "");
	fclose($fh);
	if (! copy ("openssl.cnf", SSL_CONF)) {
		return "ERR: openssl copy goes wrong ";
	}
	return "MSG: Installation done !";
}
?>
