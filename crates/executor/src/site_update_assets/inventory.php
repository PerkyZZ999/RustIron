<?php
// Fixed D-087 (W530) inventory script, run by the site's own PHP in its own
// SELinux domain with no network. It reports the installed WordPress core
// version and database version and each plugin and theme with its version,
// from headers only: get_plugins() and wp_get_themes() load no plugin or
// theme code. It changes nothing but its report in the site's tmp: no
// update cache is cleared.
declare(strict_types=1);
$status = file_get_contents('/proc/self/status');
preg_match('/^Uid:\s+(\d+)/m', $status, $uid);
$self = posix_getpwuid((int) $uid[1])['name'];
$_SERVER['REQUEST_URI'] = '/';
// Load WordPress without running the active plugins or theme.
define('WP_INSTALLING', true);
require "/srv/sites/$self/html/wp-load.php";
require_once ABSPATH . 'wp-admin/includes/plugin.php';
global $wp_version, $wp_db_version;
$plugins = [];
foreach (get_plugins() as $file => $data) {
    $folder = dirname($file);
    $plugins[] = [
        'folder' => $folder === '.' ? null : $folder,
        'file' => $file,
        'version' => (string) $data['Version'],
        'active' => is_plugin_active($file),
    ];
}
$themes = [];
$active = get_stylesheet();
foreach (wp_get_themes() as $slug => $theme) {
    $themes[] = [
        'folder' => (string) $slug,
        'version' => (string) $theme->get('Version'),
        'active' => $slug === $active,
    ];
}
file_put_contents("/srv/sites/$self/tmp/rustiron-update-inventory.json", json_encode([
    'user' => $self,
    'core' => [
        'version' => (string) $wp_version,
        'db_version' => (int) $wp_db_version,
        'db_current' => (int) get_option('db_version') === (int) $wp_db_version,
    ],
    'plugins' => $plugins,
    'themes' => $themes,
], JSON_THROW_ON_ERROR));
