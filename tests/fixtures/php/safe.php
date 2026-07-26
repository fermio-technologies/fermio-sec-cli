<?php

$hash = password_hash($password, PASSWORD_DEFAULT);
echo htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
