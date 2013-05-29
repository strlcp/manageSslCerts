<?php
/* simple testfile */
include ("orgCerts.inc.php");


$passwd = "32309r4uk";
// for the first install !
new instDir($passwd); 


$ca = new orCerA();
print "\n\n";
print "login ...\n";
print var_dump ($ca->ckCa($passwd)); 


$string = "www-server";

try {
//  print var_dump ($ca->crCrt($string, $passwd));
//	print var_dump ($ca->crRole($string, $passwd));
//	print var_dump ($ca->crUser("bla"));
} catch(InvalidArgumentException $e) {
	echo $e->getMessage();
	$string .= mt_rand(0, 9);
	print "calling again with different value \n";	
	$string .= "l";	
	print_r ($string);
//	print var_dump ($ca->crCrt($string, $passwd));
//	print var_dump ($ca->crRole($string, $passwd));
//	print var_dump ($ca->crUser("bla". $string));
} 

// print "login restricted \n ";

 $caR = new orCerA($string);
 print var_dump ($caR->ckCa($passwd)); 
#	print var_dump ($caR->crCrt($string, $passwd));
	print var_dump ($caR->crCrt("www-browser", $passwd));
/*

*/


?>
