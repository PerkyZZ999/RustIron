<?php
// Fixed S04 install script (recipe wordpress713_install_v1), run once by the
// site's own PHP in its own SELinux domain with no network. Reads the generated
// admin secret from a site-owned file in its own tmp and removes it first.
declare(strict_types=1);
$status = file_get_contents('/proc/self/status');
preg_match('/^Uid:\s+(\d+)/m', $status, $uid);
$self = posix_getpwuid((int) $uid[1])['name'];
$tmp = "/srv/sites/$self/tmp";
$secret = trim((string) file_get_contents("$tmp/rustiron-install.secret"));
$removed = unlink("$tmp/rustiron-install.secret");
$input = json_decode((string) file_get_contents("$tmp/rustiron-install.input"), true, 4, JSON_THROW_ON_ERROR);
$host = (string) $input['host'];
$_SERVER['HTTP_HOST'] = $host;
$_SERVER['REQUEST_URI'] = '/';
define('WP_INSTALLING', true);
define('WP_SITEURL', "http://$host");
define('WP_HOME', "http://$host");
// No mail from the lab install; WordPress defines its own only if absent.
function wp_new_blog_notification($blog_title, $blog_url, $user_id, $password): void
{
}
require "/srv/sites/$self/html/wp-load.php";
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
$before = is_blog_installed();
if (!$before && strlen($secret) === 48) {
    wp_install((string) $input['title'], 'rustiron_admin', "admin@$host", false, '', $secret);
}
$user = get_user_by('login', 'rustiron_admin');
file_put_contents("$tmp/rustiron-install.json", json_encode([
    'user' => $self,
    'already_installed' => $before,
    'installed' => is_blog_installed(),
    'admin_is_administrator' => $user !== false && in_array('administrator', $user->roles, true),
    'password_ok' => $user !== false && wp_check_password($secret, $user->user_pass, $user->ID),
    'secret_removed' => $removed && !file_exists("$tmp/rustiron-install.secret"),
    'siteurl' => get_option('siteurl'),
]));
