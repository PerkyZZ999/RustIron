<?php
// Rustiron site import, Verify step (W451, D-053).
//
// Run by the site's own PHP in its own SELinux domain after the import steps
// and the PHP units. It takes no input. It reports the identity it runs as,
// its database login, the imported tables and site URL, that it cannot
// write its code, and that it cannot read another site. It reads no
// password into the report.
declare(strict_types=1);
$status = file_get_contents('/proc/self/status');
preg_match('/^Uid:\s+(\d+)/m', $status, $uid);
$self = posix_getpwuid((int) $uid[1])['name'];
$root = "/srv/sites/$self";
$cnf = parse_ini_file("$root/private/db.cnf", true, INI_SCANNER_RAW)['client'];
$db = new mysqli('localhost', $cnf['user'], $cnf['password'], $cnf['database'], 0, $cnf['socket']);
unset($cnf);
$row = $db->query('SELECT DATABASE(), CURRENT_USER()')->fetch_row();
$tables = (int) $db->query('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()')->fetch_row()[0];
$siteurl = null;
$options = (int) $db->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'wp_options'")->fetch_row()[0];
if ($options === 1) {
    $result = $db->query("SELECT option_value FROM wp_options WHERE option_name = 'siteurl'");
    if ($result->num_rows === 1) {
        $siteurl = substr((string) $result->fetch_row()[0], 0, 2048);
    }
}
$others = [];
foreach (scandir('/srv/sites') as $site) {
    if ($site[0] !== '.' && $site !== $self) {
        $others[$site] = @scandir("/srv/sites/$site/html") !== false;
    }
}
file_put_contents("$root/tmp/rustiron-import-verify.json", json_encode([
    'user' => $self,
    'context' => trim((string) file_get_contents('/proc/self/attr/current'), "\0\n"),
    'database' => $row[0],
    'db_user' => $row[1],
    'tables' => $tables,
    'siteurl' => $siteurl,
    'wp_config' => is_readable("$root/html/wp-config.php"),
    'can_write_html' => is_writable("$root/html/wp-config.php") || is_writable("$root/html"),
    'reads_other_sites' => $others,
]));
