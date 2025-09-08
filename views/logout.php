<?php
session_start();
session_unset();
session_destroy();
setcookie('token', '', time() - 3600, '/');
header("Location: " . $_GET['redirect']);
exit();
?>