<?php
// Fixed W368 compensation script: deactivate the LiteSpeed Cache plugin as
// the site, in its own SELinux domain with no network, after a failed
// opt-in check. The plugin files stay; nothing is deleted.
declare(strict_types=1);
$status = file_get_contents('/proc/self/status');
preg_match('/^Uid:\s+(\d+)/m', $status, $uid);
$self = posix_getpwuid((int) $uid[1])['name'];
$tmp = "/srv/sites/$self/tmp";
$_SERVER['REQUEST_URI'] = '/';
// The code is read-only to the site; without this WordPress picks the FTP
// filesystem and the plugin's file checks fail fatally (W368 VM run 1).
define('FS_METHOD', 'direct');
require "/srv/sites/$self/html/wp-load.php";
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = 'litespeed-cache/litespeed-cache.php';
if (is_plugin_active($plugin)) {
    deactivate_plugins($plugin);
}
file_put_contents("$tmp/rustiron-page-cache-off.json", json_encode([
    'user' => $self,
    'active' => is_plugin_active($plugin),
]));
