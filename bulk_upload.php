<?php

require_once('database.php');
require_once('helpers.php');

$ERROR = "bulk_error.log";
$CWD = ".";
//$TOTAL_CERTS
//$BATCH_SIZE = 5;

$db = new Database($c['mysql_host'], $c['mysql_username'], $c['mysql_password'], $c['mysql_database']);

$query = "select raw_cert from certs";
$res = $db->results_query($query);


print count($res);
//print_r($res);
//exit(1);

foreach ($res as $cert_arr) {
  //$uncert = array_shift($cert_arr);
  $cert = base64_encode($cert_arr[0]);
  //$fp = cert_hash($cert);
  //print "Processing ".$fp."\n";
  $db->parse_cert($cert, $ERROR, $CWD);
}

?>