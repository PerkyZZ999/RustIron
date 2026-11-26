<?php
// Rustiron site import, Config step (W450, D-053).
//
// Runs as the site account in its PHP sandbox from <site root>/tmp. It reads
// the imported html/wp-config.php and replaces its four database
// definitions with Rustiron's runtime read of private/db.cnf, so the source
// host's credentials leave the site's code. It refuses unless DB_NAME,
// DB_USER, DB_PASSWORD, and DB_HOST are each defined exactly once as
// define('NAME', 'plain string literal');. It writes only the new text and a
// report into tmp; root installs the text. No value from the file is
// printed: the report holds fixed fields only.
//
// D-069 (W478): the source's absolute document root (from Rustiron's input
// rustiron-import-config.paths, built from the signed hostname) is replaced
// by this site's html path in wp-config.php, the document root .htaccess and
// .user.ini, and the direct .php children of wp-content. Each other changed
// file is written to tmp as rustiron-import-path.<n>; the report lists its
// relative name and digest, and root installs it.
declare(strict_types=1);

const LIMIT = 1048576;
const WANTED = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'];
const READER = <<<'PHP'
$rustiron_db = parse_ini_file(dirname(__DIR__) . '/private/db.cnf', true, INI_SCANNER_RAW)['client'];
define('DB_NAME', $rustiron_db['database']);
define('DB_USER', $rustiron_db['user']);
define('DB_PASSWORD', $rustiron_db['password']);
define('DB_HOST', 'localhost:' . $rustiron_db['socket']);
unset($rustiron_db);
PHP;

$tmp = __DIR__;
$root = dirname($tmp);

function finish(string $tmp, array $value): never
{
    file_put_contents($tmp . '/rustiron-import-config.json', json_encode($value));
    exit(0);
}

function skip(array $tokens, int $i): int
{
    $n = count($tokens);
    while ($i < $n && is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
        $i++;
    }
    return $i;
}

function literal(mixed $token): ?string
{
    if (!is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
        return null;
    }
    $text = $token[1];
    // A single-quoted literal only: no interpolation, no escapes but \' and \\.
    if (strlen($text) < 2 || $text[0] !== "'" || substr($text, -1) !== "'") {
        return null;
    }
    return substr($text, 1, -1);
}

$source = @file_get_contents($root . '/html/wp-config.php', false, null, 0, LIMIT + 1);
if (!is_string($source) || strlen($source) > LIMIT) {
    finish($tmp, ['ok' => false, 'reason' => 'read']);
}
try {
    $tokens = token_get_all($source, TOKEN_PARSE);
} catch (ParseError) {
    finish($tmp, ['ok' => false, 'reason' => 'parse']);
}
$n = count($tokens);
$found = [];
for ($i = 0; $i < $n; $i++) {
    $token = $tokens[$i];
    if (!is_array($token) || $token[0] !== T_STRING || strtolower($token[1]) !== 'define') {
        continue;
    }
    // Not a method or a function declaration named define.
    $before = $i - 1;
    while ($before >= 0 && is_array($tokens[$before]) && in_array($tokens[$before][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
        $before--;
    }
    if ($before >= 0 && is_array($tokens[$before])
        && in_array($tokens[$before][0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true)) {
        continue;
    }
    $j = skip($tokens, $i + 1);
    if (($tokens[$j] ?? null) !== '(') {
        continue;
    }
    $j = skip($tokens, $j + 1);
    $name = literal($tokens[$j] ?? null);
    if ($name === null && is_array($tokens[$j] ?? null) && $tokens[$j][0] === T_CONSTANT_ENCAPSED_STRING) {
        $name = trim($tokens[$j][1], '"');
    }
    if ($name === null || !in_array($name, WANTED, true)) {
        continue;
    }
    if (isset($found[$name])) {
        finish($tmp, ['ok' => false, 'reason' => 'repeated']);
    }
    $j = skip($tokens, $j + 1);
    if (($tokens[$j] ?? null) !== ',') {
        finish($tmp, ['ok' => false, 'reason' => 'not_plain']);
    }
    $j = skip($tokens, $j + 1);
    if (literal($tokens[$j] ?? null) === null) {
        finish($tmp, ['ok' => false, 'reason' => 'not_plain']);
    }
    $j = skip($tokens, $j + 1);
    if (($tokens[$j] ?? null) !== ')') {
        finish($tmp, ['ok' => false, 'reason' => 'not_plain']);
    }
    $j = skip($tokens, $j + 1);
    if (($tokens[$j] ?? null) !== ';') {
        finish($tmp, ['ok' => false, 'reason' => 'not_plain']);
    }
    $found[$name] = [$i, $j];
}
if (count($found) !== count(WANTED)) {
    finish($tmp, ['ok' => false, 'reason' => 'missing']);
}
$starts = array_column($found, 0);
$first = min($starts);
$output = '';
for ($i = 0; $i < $n; $i++) {
    foreach ($found as [$start, $end]) {
        if ($i >= $start && $i <= $end) {
            if ($i === $first) {
                $output .= READER;
            }
            continue 2;
        }
    }
    $output .= is_array($tokens[$i]) ? $tokens[$i][1] : $tokens[$i];
}
$input = @file_get_contents($tmp . '/rustiron-import-config.paths', false, null, 0, 4096);
$old = is_string($input) ? trim($input) : '';
if (preg_match('#^/home/[a-z0-9][a-z0-9.-]{0,252}/public_html$#', $old) !== 1) {
    finish($tmp, ['ok' => false, 'reason' => 'paths_input']);
}
$new = $root . '/html';
// The old root itself or anything below it, never a sibling such as
// public_html.old-<date>.
$pattern = '#' . preg_quote($old, '#') . '(?![A-Za-z0-9._-])#';
$move = static fn (string $text): string => preg_replace($pattern, $new, $text);
$output = $move($output);
$candidates = ['.htaccess', '.user.ini'];
$content = $root . '/html/wp-content';
if (is_dir($content) && !is_link($content)) {
    foreach (scandir($content) ?: [] as $name) {
        if (preg_match('/^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}\.php$/', $name) === 1) {
            $candidates[] = 'wp-content/' . $name;
        }
    }
}
if (count($candidates) > 66) {
    finish($tmp, ['ok' => false, 'reason' => 'paths_count']);
}
$paths = [];
foreach ($candidates as $name) {
    $file = $root . '/html/' . $name;
    if (is_link($file) || !is_file($file)) {
        continue;
    }
    $text = @file_get_contents($file, false, null, 0, LIMIT + 1);
    if (!is_string($text) || strlen($text) > LIMIT) {
        finish($tmp, ['ok' => false, 'reason' => 'paths_read']);
    }
    $moved = $move($text);
    if ($moved === $text) {
        continue;
    }
    $out = $tmp . '/rustiron-import-path.' . count($paths);
    if (file_put_contents($out, $moved) !== strlen($moved)) {
        finish($tmp, ['ok' => false, 'reason' => 'write']);
    }
    $paths[] = ['name' => $name, 'sha256' => hash('sha256', $moved)];
}
if (file_put_contents($tmp . '/rustiron-import-config.new', $output) !== strlen($output)) {
    finish($tmp, ['ok' => false, 'reason' => 'write']);
}
finish($tmp, ['ok' => true, 'reason' => null, 'replaced' => count($found), 'sha256' => hash('sha256', $output), 'paths' => $paths]);
