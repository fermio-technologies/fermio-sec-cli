<?php

system($_GET['cmd']);
echo $_GET['name'];

$pdo = new PDO('sqlite::memory:');
$pdo->query($_GET['sql']);
