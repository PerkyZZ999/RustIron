<?php
// Rustiron site import, Config step: the hostname change of D-070.
//
// Runs as the site account in its PHP sandbox from <site root>/tmp, after
// the Database step, only for an import whose signed plan serves the site
// under another hostname. Its input rustiron-import-urls.input holds two
// lines from the signed plan: the source hostname and the target hostname.
//
// In every base table of the site's own database, it replaces each
// //<source> (and the JSON form \/\/<source>) that ends the hostname with
// //<target>. Serialized PHP values are rewritten by walking their text: no
// value is unserialized, so no object is built, and each changed string
// gets its new length. A value that looks serialized but does not parse is
// left as it is and counted. The guid column is left unchanged: it is an
// identifier, not a link. Mail addresses (no //) are never changed.
//
// W479-F1: derived caches can hold the source hostname in a form no text
// search sees (Elementor's element cache keeps each element's settings in
// base64). In the same transaction the asset deletes the caches that
// WordPress and Elementor rebuild on demand: every transient and site
// transient row of an options table, and every _elementor_element_cache row
// of a postmeta table.
//
// The report holds counts only, never a value.
declare(strict_types=1);

const MAX_DEPTH = 32;
const MAX_ROWS = 500000;
const TEXT_TYPES = ['char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext'];
const CHARSETS = ['utf8mb4', 'utf8mb3', 'utf8', 'latin1', 'ascii'];

$tmp = __DIR__;
$root = dirname($tmp);

function finish(string $tmp, array $value): never
{
    file_put_contents($tmp . '/rustiron-import-urls.json', json_encode($value));
    exit(0);
}

$input = @file_get_contents($tmp . '/rustiron-import-urls.input', false, null, 0, 1024);
$lines = is_string($input) ? explode("\n", rtrim($input, "\n")) : [];
$host = '/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/';
if (count($lines) !== 2 || preg_match($host, $lines[0]) !== 1 || preg_match($host, $lines[1]) !== 1
    || $lines[0] === $lines[1]) {
    finish($tmp, ['ok' => false, 'reason' => 'input']);
}
[$source, $target] = $lines;

// //source or \/\/source, where the hostname ends: not followed by a
// hostname character, nor by a dot and a hostname character.
$pattern = '#(?<=//|\\\\/\\\\/)' . preg_quote($source, '#') . '(?![A-Za-z0-9-]|\.[A-Za-z0-9])#';
$needles = ['//' . $source, '\\/\\/' . $source];

$counts = ['tables' => 0, 'columns' => 0, 'rows' => 0, 'values' => 0, 'serialized' => 0, 'unparsed' => 0, 'caches' => 0];

/** Replaces plain text; a serialized string inside is walked first. */
function plain(string $text, int $depth): ?string
{
    global $pattern;
    // A string holding a whole serialized value (double serialization) is
    // walked; one that does not parse is text.
    if ($depth < 4 && looks_serialized($text)) {
        $i = 0;
        $walked = walk($text, $i, $depth + 1);
        if ($walked !== null && $i === strlen($text)) {
            return $walked;
        }
    }
    $out = preg_replace($pattern, $GLOBALS['target'], $text);
    return is_string($out) ? $out : null;
}

/** A strict serialized shape: a full value prefix, and a closing ; or }. */
function looks_serialized(string $text): bool
{
    return $text === 'N;'
        || (preg_match('/^(?:a:\d+:\{|O:\d+:"|C:\d+:"|s:\d+:"|E:\d+:"|i:[+-]?\d+;|b:[01];|d:[^;]{1,64};)/', $text) === 1
            && in_array(substr($text, -1), [';', '}'], true));
}

/**
 * Walks one serialized value at $i and returns it with every string value
 * replaced; keys, class names, and custom-serialized (C:) data unchanged.
 * Returns null when the text is not a well-formed serialized value.
 */
function walk(string $s, int &$i, int $depth): ?string
{
    if ($depth > MAX_DEPTH || $i >= strlen($s)) {
        return null;
    }
    $at = static fn (string $re, ?array &$m) => preg_match($re, $s, $m, 0, $i) === 1;
    $m = null;
    switch ($s[$i]) {
        case 'N':
            if (substr($s, $i, 2) !== 'N;') {
                return null;
            }
            $i += 2;
            return 'N;';
        case 'b':
        case 'i':
        case 'd':
        case 'r':
        case 'R':
            if (!$at('/\G(?:b:[01]|i:[+-]?\d+|d:(?:[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?|NAN|-?INF)|[rR]:\d+);/', $m)) {
                return null;
            }
            $i += strlen($m[0]);
            return $m[0];
        case 's':
            if (!$at('/\Gs:(\d+):"/', $m)) {
                return null;
            }
            $length = (int) $m[1];
            $start = $i + strlen($m[0]);
            if ($start + $length + 2 > strlen($s) || substr($s, $start + $length, 2) !== '";') {
                return null;
            }
            $value = substr($s, $start, $length);
            $i = $start + $length + 2;
            $new = plain($value, $depth);
            if ($new === null) {
                return null;
            }
            return 's:' . strlen($new) . ':"' . $new . '";';
        case 'E':
            if (!$at('/\GE:(\d+):"/', $m)) {
                return null;
            }
            $end = $i + strlen($m[0]) + (int) $m[1];
            if ($end + 2 > strlen($s) || substr($s, $end, 2) !== '";') {
                return null;
            }
            $copy = substr($s, $i, $end + 2 - $i);
            $i = $end + 2;
            return $copy;
        case 'C':
            if (!$at('/\GC:(\d+):"[^"]*":(\d+):\{/', $m)) {
                return null;
            }
            $end = $i + strlen($m[0]) + (int) $m[2];
            if ($end >= strlen($s) || $s[$end] !== '}') {
                return null;
            }
            $copy = substr($s, $i, $end + 1 - $i);
            $i = $end + 1;
            return $copy;
        case 'a':
        case 'O':
            if (!$at('/\G(?:a|O:\d+:"[^"]*"):(\d+):\{/', $m)) {
                return null;
            }
            $head = $m[0];
            $count = (int) $m[1];
            $i += strlen($head);
            $out = $head;
            for ($n = 0; $n < $count; $n++) {
                // The key or property name stays as it is.
                $keyStart = $i;
                if (walk_key($s, $i) === null) {
                    return null;
                }
                $out .= substr($s, $keyStart, $i - $keyStart);
                $value = walk($s, $i, $depth + 1);
                if ($value === null) {
                    return null;
                }
                $out .= $value;
            }
            if ($i >= strlen($s) || $s[$i] !== '}') {
                return null;
            }
            $i++;
            return $out . '}';
    }
    return null;
}

/** Skips one array key or property name: an integer or a string. */
function walk_key(string $s, int &$i): ?bool
{
    if (preg_match('/\Gi:[+-]?\d+;/', $s, $m, 0, $i) === 1) {
        $i += strlen($m[0]);
        return true;
    }
    if (preg_match('/\Gs:(\d+):"/', $s, $m, 0, $i) === 1) {
        $end = $i + strlen($m[0]) + (int) $m[1];
        if ($end + 2 > strlen($s) || substr($s, $end, 2) !== '";') {
            return null;
        }
        $i = $end + 2;
        return true;
    }
    return null;
}

/** The new value, or null to leave it (unchanged or unparsed). */
function rewrite(string $value, array &$counts): ?string
{
    if (looks_serialized($value)) {
        $i = 0;
        $walked = walk($value, $i, 0);
        if ($walked === null || $i !== strlen($value)) {
            $counts['unparsed']++;
            return null;
        }
        if ($walked === $value) {
            return null;
        }
        $counts['serialized']++;
        return $walked;
    }
    $new = plain($value, 0);
    return ($new === null || $new === $value) ? null : $new;
}

function quote(string $name): string
{
    return '`' . str_replace('`', '``', $name) . '`';
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $cnf = parse_ini_file($root . '/private/db.cnf', true, INI_SCANNER_RAW)['client'] ?? null;
    if (!is_array($cnf)) {
        finish($tmp, ['ok' => false, 'reason' => 'credentials']);
    }
    $db = new mysqli('localhost', $cnf['user'], $cnf['password'], $cnf['database'], 0, $cnf['socket']);
    unset($cnf);
    // Bytes in and out as stored: no character set conversion.
    $db->query('SET NAMES binary');
    $tables = $db->query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME")->fetch_all();
    $db->begin_transaction();
    foreach ($tables as [$table]) {
        $counts['tables']++;
        $columns = $db->execute_query(
            'SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_SET_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION',
            [$table]
        )->fetch_all();
        $keys = array_column($db->execute_query(
            "SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = 'PRIMARY' ORDER BY SEQ_IN_INDEX",
            [$table]
        )->fetch_all(), 0);
        foreach ($columns as [$column, $type, $charset]) {
            if (!in_array(strtolower((string) $type), TEXT_TYPES, true)
                || !in_array(strtolower((string) $charset), CHARSETS, true)
                || strtolower((string) $column) === 'guid'
                || in_array($column, $keys, true)) {
                continue;
            }
            $counts['columns']++;
            $q = quote($column);
            $match = "INSTR(CAST($q AS BINARY), ?) > 0 OR INSTR(CAST($q AS BINARY), ?) > 0";
            if ($keys !== []) {
                $keyList = implode(', ', array_map('quote', $keys));
                $where = implode(' AND ', array_map(static fn ($k) => quote($k) . ' <=> ?', $keys));
                $rows = $db->execute_query("SELECT $keyList FROM " . quote($table) . " WHERE $match", $needles)->fetch_all();
                foreach ($rows as $key) {
                    $value = $db->execute_query("SELECT $q FROM " . quote($table) . " WHERE $where", $key)->fetch_row()[0] ?? null;
                    if (!is_string($value)) {
                        continue;
                    }
                    $new = rewrite($value, $counts);
                    if ($new === null) {
                        continue;
                    }
                    $db->execute_query('UPDATE ' . quote($table) . " SET $q = ? WHERE $where", array_merge([$new], $key));
                    $counts['rows']++;
                    $counts['values']++;
                    if ($counts['rows'] > MAX_ROWS) {
                        $db->rollback();
                        finish($tmp, ['ok' => false, 'reason' => 'rows']);
                    }
                }
            } else {
                // No primary key: update each distinct value in place.
                $values = $db->execute_query("SELECT DISTINCT $q FROM " . quote($table) . " WHERE $match", $needles)->fetch_all();
                foreach ($values as [$value]) {
                    if (!is_string($value)) {
                        continue;
                    }
                    $new = rewrite($value, $counts);
                    if ($new === null) {
                        continue;
                    }
                    $db->execute_query('UPDATE ' . quote($table) . " SET $q = ? WHERE CAST($q AS BINARY) = ?", [$new, $value]);
                    $counts['rows'] += $db->affected_rows;
                    $counts['values']++;
                    if ($counts['rows'] > MAX_ROWS) {
                        $db->rollback();
                        finish($tmp, ['ok' => false, 'reason' => 'rows']);
                    }
                }
            }
        }
    }
    // W479-F1: the disposable caches, by table shape, whatever the prefix.
    $shape = static fn (string $table, string $column): bool => (int) $db->execute_query(
        'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
        [$table, $column]
    )->fetch_row()[0] === 1;
    foreach ($tables as [$table]) {
        if (str_ends_with($table, 'options') && $shape($table, 'option_name')) {
            $db->query('DELETE FROM ' . quote($table) . " WHERE option_name LIKE '\\_transient\\_%' OR option_name LIKE '\\_site\\_transient\\_%'");
            $counts['caches'] += $db->affected_rows;
        } elseif (str_ends_with($table, 'postmeta') && $shape($table, 'meta_key')) {
            $db->query('DELETE FROM ' . quote($table) . " WHERE meta_key = '_elementor_element_cache'");
            $counts['caches'] += $db->affected_rows;
        }
    }
    $db->commit();
} catch (Throwable) {
    finish($tmp, ['ok' => false, 'reason' => 'database']);
}
finish($tmp, ['ok' => true, 'reason' => null] + $counts);
