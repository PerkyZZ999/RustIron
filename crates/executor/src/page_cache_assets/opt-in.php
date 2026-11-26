<?php
// Fixed W368 page-cache opt-in script (recipe litespeed_cache_793_v1), run
// once by the site's own PHP in its own SELinux domain with no network. It
// reads only the fixed settings file the executor placed in the site's tmp.
// Order: store the fixed settings first, so the plugin never starts with its
// default page cache on; then activate the pinned plugin; then end every
// login session (a session from before has no _lscache_vary cookie); then
// report what WordPress and the plugin read back.
// W370: settings keep their JSON type (lists stay lists), and the report
// says whether the must-use lock file's constants are in force.
declare(strict_types=1);
$status = file_get_contents('/proc/self/status');
preg_match('/^Uid:\s+(\d+)/m', $status, $uid);
$self = posix_getpwuid((int) $uid[1])['name'];
$tmp = "/srv/sites/$self/tmp";
$settings = json_decode((string) file_get_contents("$tmp/rustiron-page-cache.settings"), true, 3, JSON_THROW_ON_ERROR);
$_SERVER['REQUEST_URI'] = '/';
// The code is read-only to the site; without this WordPress picks the FTP
// filesystem and the plugin's file checks fail fatally (W368 VM run 1).
define('FS_METHOD', 'direct');
require "/srv/sites/$self/html/wp-load.php";
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = 'litespeed-cache/litespeed-cache.php';
$data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
$before = is_plugin_active($plugin);
$activated = 'not_run';
if (!$before && $data['Version'] === '7.9.3') {
    foreach ($settings as $key => $value) {
        update_option("litespeed.conf.$key", $value);
    }
    $result = activate_plugin($plugin);
    $activated = is_wp_error($result) ? 'error' : 'ok';
}
WP_Session_Tokens::destroy_all_for_all_users();
global $wpdb;
$sessions = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'");
wp_cache_flush();
$stored = [];
$view = [];
$locked = 0;
$conf = class_exists('\LiteSpeed\Conf') ? \LiteSpeed\Conf::cls() : null;
if ($conf !== null) {
    $conf->load_options();
}
foreach ($settings as $key => $_) {
    $stored[$key] = get_option("litespeed.conf.$key");
    if (!is_array($stored[$key])) {
        $stored[$key] = (string) $stored[$key];
    }
    $view[$key] = $conf !== null ? $conf->conf($key) : null;
    if (defined('LITESPEED_CONF__' . strtoupper(str_replace('-', '__', $key)))) {
        $locked++;
    }
}
file_put_contents("$tmp/rustiron-page-cache.json", json_encode([
    'user' => $self,
    'version' => $data['Version'],
    'active_before' => $before,
    'activated' => $activated,
    'active' => is_plugin_active($plugin),
    'settings' => $stored,
    'plugin_view' => $view,
    'lock_on' => defined('LITESPEED_CONF') && LITESPEED_CONF === true,
    'locked' => $locked,
    'sessions' => $sessions,
]));
