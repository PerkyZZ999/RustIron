<?php
// Fixed D-084 (W516) update script, run by the site's own PHP in its own
// SELinux domain with no network. It reads only the component list that the
// executor placed in the site's tmp (`kind slug` lines), clears WordPress's
// stored update checks, and reports the installed version of each
// component from its headers. It loads no plugin or theme code: get_plugins()
// and wp_get_theme() read headers only.
// W527 (D-086): a `core wordpress` line reports the loaded $wp_version. The
// line `core wordpress upgrade`, after the swap, first runs wp_upgrade() for
// the new release's database version and reports the version only when the
// stored database version is then the release's.
declare(strict_types=1);
$status = file_get_contents('/proc/self/status');
preg_match('/^Uid:\s+(\d+)/m', $status, $uid);
$self = posix_getpwuid((int) $uid[1])['name'];
$tmp = "/srv/sites/$self/tmp";
$lines = file("$tmp/rustiron-update.components", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$_SERVER['REQUEST_URI'] = '/';
// The code is read-only to the site (see the page-cache scripts).
define('FS_METHOD', 'direct');
// Load WordPress without running the active plugins or theme.
define('WP_INSTALLING', true);
require "/srv/sites/$self/html/wp-load.php";
require_once ABSPATH . 'wp-admin/includes/plugin.php';
delete_site_transient('update_plugins');
delete_site_transient('update_themes');
wp_clean_plugins_cache(false);
$report = [];
foreach ($lines as $line) {
    $parts = explode(' ', $line);
    [$kind, $slug] = $parts;
    $version = null;
    if ($kind === 'plugin') {
        $found = get_plugins('/' . $slug);
        if (count($found) === 1) {
            $version = (string) array_values($found)[0]['Version'];
        }
    } elseif ($kind === 'core' && $slug === 'wordpress') {
        if (($parts[2] ?? '') === 'upgrade') {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            wp_upgrade();
            wp_cache_flush();
        }
        global $wp_version, $wp_db_version;
        if ((int) get_option('db_version') === (int) $wp_db_version) {
            $version = (string) $wp_version;
        }
    } elseif ($kind === 'theme') {
        $theme = wp_get_theme($slug);
        if ($theme->exists()) {
            $version = (string) $theme->get('Version');
        }
    }
    $report[] = ['kind' => $kind, 'slug' => $slug, 'version' => $version];
}
file_put_contents("$tmp/rustiron-update.json", json_encode([
    'user' => $self,
    'components' => $report,
], JSON_THROW_ON_ERROR));
