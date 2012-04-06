<?php

require_once('database.php');
require_once('helpers.php');
require_once('config.php');

$ERROR = "bulk_error.log";
$CWD = ".";
$BATCH_SIZE = 10000;
//$TOTAL_CERTS
//$BATCH_SIZE = 5;

$db = new Database($c['mysql_host'], $c['mysql_username'], $c['mysql_password'], $c['mysql_database']);

for ($i=1; $i < 32; $i++) {
  print "Working on batch ".$i."\n";
  $val = $i * $BATCH_SIZE;
  $query = "select raw_cert from certs limit ".$val.", ".$BATCH_SIZE;
  $res = $db->results_query($query);
  foreach ($res as $cert_arr) {
    $cert = base64_encode($cert_arr[0]);
    $db->parse_cert($cert, $ERROR, $CWD);
  }
}

?>