<?php
// Fixed S04 Verify probe, run by the site's own PHP in its own SELinux domain.
// Reports identity and what the site can reach into its own tmp; takes no input.
declare(strict_types=1);
$status = file_get_contents('/proc/self/status');
preg_match('/^Uid:\s+(\d+)/m', $status, $uid);
$self = posix_getpwuid((int) $uid[1])['name'];
$root = "/srv/sites/$self";
$cnf = parse_ini_file("$root/private/db.cnf", true, INI_SCANNER_RAW)['client'];
$db = new mysqli('localhost', $cnf['user'], $cnf['password'], $cnf['database'], 0, $cnf['socket']);
$row = $db->query('SELECT DATABASE(), CURRENT_USER()')->fetch_row();
// W399: installed means the WordPress tables hold the site URL and the fixed
// administrator login; a site without them answers with its installer.
$tables = (int) $db->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ('wp_options', 'wp_users')")->fetch_row()[0];
$installed = $tables === 2
    && (int) $db->query("SELECT COUNT(*) FROM wp_options WHERE option_name = 'siteurl'")->fetch_row()[0] === 1
    && (int) $db->query("SELECT COUNT(*) FROM wp_users WHERE user_login = 'rustiron_admin'")->fetch_row()[0] === 1;
$others = [];
foreach (scandir('/srv/sites') as $site) {
    if ($site[0] !== '.' && $site !== $self) {
        $others[$site] = @scandir("/srv/sites/$site/html") !== false;
    }
}
// Per-file core checksums from the pinned upstream list (placed by the
// executor); every listed file must exist and match.
$core = ['checked' => 0, 'mismatched' => 0, 'missing' => 0];
$list = json_decode((string) file_get_contents("$root/tmp/rustiron-verify.checksums"), true, 4, JSON_THROW_ON_ERROR);
foreach ($list['checksums'] as $path => $md5) {
    $core['checked']++;
    $file = "$root/html/$path";
    if (str_contains($path, '..') || !is_file($file)) {
        $core['missing']++;
    } elseif (md5_file($file) !== $md5) {
        $core['mismatched']++;
    }
}
file_put_contents("$root/tmp/rustiron-verify.json", json_encode([
    'user' => $self,
    'context' => trim((string) file_get_contents('/proc/self/attr/current'), "\0\n"),
    'database' => $row[0],
    'db_user' => $row[1],
    'wp_config' => is_readable("$root/html/wp-config.php"),
    'version' => is_readable("$root/html/wp-includes/version.php"),
    'can_write_html' => is_writable("$root/html/index.php"),
    'reads_other_sites' => $others,
    'core' => $core,
    'installed' => $installed,
]));
