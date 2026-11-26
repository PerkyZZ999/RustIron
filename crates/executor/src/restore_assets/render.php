<?php
// D-034 (W383): render the restored WordPress home page. Run as the throwaway
// probe account in rustiron_php_t with no network. It takes the restored site
// root and the site's hostname. The page itself is the only output: PID 1
// writes stdout to a root-owned file outside the sandbox. This script writes
// no report, and the probe verdict does not come from restored code.
declare(strict_types=1);
[$root, $host] = [$argv[1], $argv[2] ?? 'localhost'];
$_SERVER['HTTP_HOST'] = $host;
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
$_SERVER['REQUEST_METHOD'] = 'GET';
require "$root/html/index.php";
