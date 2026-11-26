<?php
// Rustiron PHP health (D-073, W487). Each managed vhost serves this one
// root-owned file at /rustiron-php-health.php, with rewriting off, through
// the site's own PHP pool. It answers with the account that PHP runs as, so
// a broken PHP build or a wrong pool fails the check while the static
// identity file still answers. It reads and writes nothing.
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
echo posix_getpwuid(posix_geteuid())['name'], "\n";
