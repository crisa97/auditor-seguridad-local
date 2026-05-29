<?php
$id = $_GET["id"];
$q = "SELECT * FROM users WHERE id = $id";
eval("\$page = " . $_GET["page"] . ";");
include($_GET["file"]);
$password = "admin123";
$cmd = "ping " . $_POST["ip"];
system($cmd);
?>
