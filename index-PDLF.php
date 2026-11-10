<?php
/**
 * PDLF — Personal Dead Link Finder 3.0
 * Self-hosted, single-file dead-link crawler for your own sites.
 *
 * Requirements : PHP 8.0+, pdo_sqlite (SQLite 3.25+), curl (with SSL), dom
 * Optional     : mbstring (legacy charsets), intl (internationalised domain names)
 * License      : MIT
 *
 * THREE-WAY LINK CLASSIFICATION
 *   WORKING     2xx, directly or after safe redirects
 *   BROKEN      404, 410, 5xx (except 503), DNS failure, invalid TLS certificate,
 *               redirect loop, too many redirects
 *   UNVERIFIED  anything that cannot be judged reliably: 401/403/405/429/503 and other
 *               4xx, timeouts, connection errors, blocked (unsafe) destinations,
 *               redirects without a Location header
 *
 * Optional overrides live in <data dir>/config.php:
 *   'allow_private_hosts' => true   (only if you must scan a private/LAN site)
 *   'ca_bundle'           => '/path/to/cacert.pem'  (if PHP cannot find CA certificates)
 *   'limits'              => ['batch_seconds' => 15, ...]  (see DEFAULT_LIMITS)
 */

declare(strict_types=1);

// ============================================================================
// CONSTANTS
// ============================================================================
const PDLF_VERSION = '1.0.0-beta.1';
const USER_AGENT = 'PDLF/1.0.0-beta.1 (+self-hosted link checker)';

const DEFAULT_LIMITS = [
    'batch_seconds'   => 20,       // stop starting new links after this long in one AJAX batch
    'link_seconds'    => 25,       // hard cap for ONE link (all redirect hops and retries together)
    'request_timeout' => 10,       // per HTTP request (the scan form can change it, 3..30)
    'connect_timeout' => 5,
    'max_redirects'   => 5,
    'max_html_bytes'  => 2097152,  // at most 2 MB of a page is downloaded and parsed
    'max_links_page'  => 2000,     // links taken from a single page
    'max_url_length'  => 2048,
    'max_links_hard'  => 20000,    // upper bound for the "Max links" field
    'allowed_ports'   => [80, 443, 8080, 8443],
    'keep_scans'      => 25,       // older scans are pruned automatically
    'keep_backups'    => 5,
];

const TRACKING_PARAMS = ['fbclid', 'gclid', 'dclid', 'msclkid', 'mc_cid', 'mc_eid', 'igshid', 'yclid', '_ga', '_gl'];
const SKIP_CRAWL_DEFAULT = 'jpg,jpeg,png,gif,svg,webp,avif,ico,bmp,pdf,zip,gz,tar,rar,7z,mp4,webm,mov,avi,mp3,wav,ogg,woff,woff2,ttf,otf,eot,css,js,json,xml,txt,csv,doc,docx,xls,xlsx,ppt,pptx,apk,exe,dmg,iso';
const SKIP_CHECK_DEFAULT = '';

const BLOCKED_V4 = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
    '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
];
const BLOCKED_V6 = [
    '::/128', '::1/128', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32',
    'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
];
const SECOND_LEVEL_SUFFIXES = [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'com.au', 'net.au', 'org.au', 'edu.au',
    'gov.au', 'co.nz', 'org.nz', 'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'firm.in',
    'gen.in', 'ind.in', 'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'com.br', 'net.br', 'org.br', 'com.cn', 'net.cn',
    'org.cn', 'gov.cn', 'co.za', 'org.za', 'com.mx', 'com.ar', 'com.tr', 'com.sg', 'com.hk', 'com.my', 'co.id',
    'co.kr', 'co.il', 'com.pk', 'com.bd', 'com.np', 'com.lk', 'com.ng', 'com.eg', 'com.sa', 'com.ua', 'com.pl',
];

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// ============================================================================
// PRIVATE STORAGE (data dir: config, SQLite, logs, backups, sessions)
// ============================================================================
function resolve_data_dir(): string
{
    $env = getenv('PDLF_DATA_DIR');
    if (is_string($env) && $env !== '') {
        return rtrim($env, '/\\');
    }
    $legacy     = __DIR__ . '/.pdlf_data';
    $candidates = [];
    $docroot    = isset($_SERVER['DOCUMENT_ROOT']) ? @realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
    if ($docroot) {
        $parent = dirname($docroot);
        if ($parent !== $docroot) {
            // Preferred: a folder next to (not inside) the public web root.
            $candidates[] = $parent . '/.pdlf_data_' . substr(sha1(__DIR__), 0, 10);
        }
    }
    $candidates[] = $legacy;

    foreach ($candidates as $c) {          // an existing installation always wins
        if (@is_file($c . '/config.php')) {
            return $c;
        }
    }
    foreach ($candidates as $c) {          // fresh install: first location we can create
        if (@is_dir($c)) {
            if (@is_writable($c)) return $c;
            continue;
        }
        if (@is_writable(dirname($c))) return $c;
    }
    return $legacy;
}

function path_inside(string $path, string $root): bool
{
    $path = str_replace('\\', '/', rtrim($path, '/\\'));
    $root = str_replace('\\', '/', rtrim($root, '/\\'));
    return $root !== '' && ($path === $root || str_starts_with($path, $root . '/'));
}

function data_dir_is_public(string $dir): bool
{
    $docroot = isset($_SERVER['DOCUMENT_ROOT']) ? @realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
    if (!$docroot) return false;
    $real = @realpath($dir) ?: $dir;
    return path_inside($real, $docroot);
}

/** URL (path only) of the probe file if the data dir lives below this script, else null. */
function data_probe_url(string $dir): ?string
{
    $real = @realpath($dir);
    $here = @realpath(__DIR__);
    if (!$real || !$here || !path_inside($real, $here) || $real === $here) return null;
    $rel  = ltrim(substr(str_replace('\\', '/', $real), strlen(str_replace('\\', '/', $here))), '/');
    $base = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
    return $base . '/' . $rel . '/probe.txt';
}

function ensure_data_dir(string $dir): bool
{
    foreach ([$dir, "$dir/logs", "$dir/backups", "$dir/sessions"] as $d) {
        if (!@is_dir($d) && !@mkdir($d, 0700, true) && !@is_dir($d)) {
            return false;
        }
    }
    $files = [
        '.htaccess' => "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Order deny,allow\n  Deny from all\n</IfModule>\n",
        'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><security><authorization><remove users=\"*\" roles=\"\" verbs=\"\" /><add accessType=\"Deny\" users=\"*\" /></authorization></security></system.webServer></configuration>\n",
        'index.html' => '',
        'probe.txt'  => 'PDLF-PROBE',
    ];
    foreach ($files as $name => $content) {
        if (!is_file("$dir/$name")) {
            @file_put_contents("$dir/$name", $content);
        }
    }
    return is_dir($dir) && is_writable($dir);
}

define('DATA_DIR', resolve_data_dir());
define('CONFIG_FILE', DATA_DIR . '/config.php');
$DATA_DIR_OK = ensure_data_dir(DATA_DIR);

function plog(string $level, string $msg): void
{
    $f = DATA_DIR . '/logs/pdlf.log';
    if (@is_file($f) && (int)@filesize($f) > 1048576) {
        @rename($f, $f . '.1');
    }
    $line = sprintf("%s [%s] %s %s\n", gmdate('Y-m-d H:i:s'), $level, $_SERVER['REMOTE_ADDR'] ?? '-', preg_replace('/[\r\n]+/', ' ', $msg));
    @file_put_contents($f, $line, FILE_APPEND | LOCK_EX);
}

function e(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ============================================================================
// SECURITY HEADERS & SESSION
// ============================================================================
function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
        || (int)($_SERVER['SERVER_PORT'] ?? 0) === 443
        || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

$NONCE = base64_encode(random_bytes(16));
header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$NONCE'; style-src 'nonce-$NONCE'; "
     . "img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
if (is_https()) {
    header('Strict-Transport-Security: max-age=31536000');
}

function start_session(): void
{
    $dir = DATA_DIR . '/sessions';
    if (is_dir($dir) && is_writable($dir)) {
        session_save_path($dir);
        if (random_int(1, 50) === 1) {       // private session dir => do our own garbage collection
            foreach (glob($dir . '/sess_*') ?: [] as $f) {
                if (@filemtime($f) < time() - 86400) @unlink($f);
            }
        }
    }
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('pdlf_sid');
    $path = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/') . '/';
    session_set_cookie_params([
        'lifetime' => 0, 'path' => $path, 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Strict',
    ]);
    session_start();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function reset_session(): void
{
    $_SESSION = [];
    session_destroy();
    session_start();
    session_regenerate_id(true);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function csrf_ok(): bool
{
    $t = (string)($_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    return $t !== '' && hash_equals((string)$_SESSION['csrf_token'], $t);
}

function self_url(): string
{
    return strtok((string)($_SERVER['REQUEST_URI'] ?? './'), '?') ?: './';
}

start_session();

// ============================================================================
// SHARED PAGE CHROME (installer, login, dashboard)
// ============================================================================
function page_head(string $title): void
{
    global $NONCE;
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= e($title) ?></title>
<style nonce="<?= e($NONCE) ?>">
  :root { --bg:#f6f7f9; --card:#fff; --line:#e3e6ea; --ink:#1f2933; --muted:#667085; --accent:#2b6cb0;
          --ok:#2f9e5b; --bad:#d64545; --warn:#c98a04; }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  body { font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; background:var(--bg); color:var(--ink); margin:0; padding:20px; }
  .wrap { max-width:1100px; margin:0 auto; }
  .narrow { max-width:420px; margin:48px auto; }
  h1 { font-size:20px; margin:0; } h1 small { font-weight:400; color:var(--muted); font-size:13px; margin-left:6px; }
  h2 { font-size:16px; margin:0 0 12px; } h3 { font-size:14px; margin:18px 0 8px; }
  .top { display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; gap:12px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px; margin-bottom:18px; }
  .row { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end; }
  .field { flex:1; min-width:170px; } .field.sm { flex:0 0 120px; min-width:110px; } .field.wide { flex:3; min-width:240px; }
  .nomargin { margin:0 !important; } th.w-status { width:92px; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  label.chk { display:flex; align-items:center; gap:6px; font-size:13px; color:var(--ink); margin:0; cursor:pointer; }
  input[type=text], input[type=password], input[type=number], select { width:100%; font:inherit; padding:8px 10px; border:1px solid #cfd5dc; border-radius:6px; background:#fff; color:var(--ink); }
  button, .btn { font:inherit; padding:8px 14px; border:1px solid var(--accent); background:var(--accent); color:#fff; border-radius:6px; cursor:pointer; font-weight:600; text-decoration:none; display:inline-block; }
  button.secondary, .btn.secondary { background:#fff; color:var(--accent); }
  button.danger { background:#fff; color:var(--bad); border-color:var(--bad); }
  button.linklike { background:none; border:none; color:var(--accent); padding:0 4px; font-weight:500; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  .muted { color:var(--muted); } .small { font-size:12px; }
  .banner { padding:10px 14px; border-radius:8px; margin-bottom:16px; font-size:13px; border:1px solid; }
  .banner.err { background:#fff5f5; border-color:#f3b4b4; color:#8a1f1f; }
  .banner.warn { background:#fffaeb; border-color:#f0d38a; color:#6b4a00; }
  .banner code, code { background:rgba(0,0,0,.06); padding:1px 5px; border-radius:4px; font-size:12px; }
  .checks { width:100%; border-collapse:collapse; font-size:13px; margin:8px 0 16px; }
  .checks td { padding:5px 4px; border-bottom:1px solid var(--line); vertical-align:top; }
  .okc { color:var(--ok); font-weight:700; } .badc { color:var(--bad); font-weight:700; } .warnc { color:var(--warn); font-weight:700; }
  .scope { display:flex; gap:18px; flex-wrap:wrap; margin:6px 0; }
  #hostBox { background:#f9fafb; border:1px dashed var(--line); border-radius:8px; padding:12px; margin-top:8px; }
  #hostList { display:flex; flex-wrap:wrap; gap:6px 18px; margin:10px 0; }
  details.adv { margin-top:12px; } details.adv summary { cursor:pointer; color:var(--accent); font-size:13px; }
  progress { width:100%; height:14px; accent-color:var(--accent); }
  .counts { display:flex; gap:10px; flex-wrap:wrap; margin:10px 0; }
  .tile { flex:1; min-width:130px; border:1px solid var(--line); border-radius:8px; padding:10px 12px; background:#fff; text-align:left; color:var(--ink); font-weight:400; }
  .tile b { display:block; font-size:22px; line-height:1.2; }
  .tile.t-working { border-left:4px solid var(--ok); } .tile.t-broken { border-left:4px solid var(--bad); }
  .tile.t-unverified { border-left:4px solid var(--warn); } .tile.t-redirected { border-left:4px solid #3b82c4; }
  .tile.t-pending, .tile.t-total { border-left:4px solid #98a2b3; }
  button.tile:hover { background:#f4f8fc; } button.tile.on { outline:2px solid var(--accent); }
  #log { font:12px/1.5 ui-monospace,Menlo,Consolas,monospace; background:#0f172a; color:#cbd5e1; padding:10px 12px; border-radius:6px; max-height:190px; overflow:auto; white-space:pre-wrap; }
  table.grid { width:100%; border-collapse:collapse; font-size:13px; }
  table.grid th, table.grid td { text-align:left; padding:8px 6px; border-bottom:1px solid var(--line); vertical-align:top; }
  table.grid th { font-size:12px; color:var(--muted); font-weight:600; }
  td.url { word-break:break-all; font:12px ui-monospace,Menlo,Consolas,monospace; }
  td.url a, .src a { color:inherit; text-decoration:none; } td.url a:hover, .src a:hover { text-decoration:underline; }
  .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:700; white-space:nowrap; }
  .b-working { background:#d9f2e3; color:#14532d; } .b-broken { background:#fde0e0; color:#7f1d1d; }
  .b-unverified { background:#fdf0c8; color:#6b4a00; } .b-pending { background:#e5e7eb; color:#374151; }
  .b-running { background:#dbeafe; color:#1e3a8a; }
  .src { font-size:12px; color:var(--muted); word-break:break-all; }
  .chain { font-size:12px; margin:4px 0 0; padding-left:18px; word-break:break-all; }
  .report-grid { display:flex; gap:24px; flex-wrap:wrap; align-items:center; margin:12px 0; }
  .cbars { flex:1; min-width:260px; }
  .cbar { display:flex; align-items:center; gap:8px; margin:3px 0; font-size:12px; }
  .cbar .code { width:42px; font-weight:700; } .cbar .track { flex:1; background:#eef1f4; border-radius:4px; height:12px; }
  .cbar .fill { display:block; height:12px; border-radius:4px; min-width:2px; }
  .cbar .fill.b-working { background:var(--ok); } .cbar .fill.b-broken { background:var(--bad); } .cbar .fill.b-unverified { background:var(--warn); }
  svg .seg { fill:none; } svg .seg-working { stroke:var(--ok); } svg .seg-broken { stroke:var(--bad); } svg .seg-unverified { stroke:var(--warn); } svg .seg-bg { stroke:#eef1f4; fill:none; }
  svg text { fill:var(--ink); font:600 15px system-ui,sans-serif; }
  .pager { display:flex; align-items:center; gap:10px; margin-top:12px; justify-content:space-between; flex-wrap:wrap; }
  .toolbar { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin:10px 0; }
  .toolbar select, .toolbar input[type=text] { width:auto; min-width:160px; }
</style>
</head>
<body>
<?php
}

function page_foot(): void
{
    echo "</body>\n</html>\n";
}

// ============================================================================
// INSTALLATION WIZARD (runs only until config.php exists)
// ============================================================================
function env_checks(bool $dataOk): array
{
    $sqliteVer = '';
    if (extension_loaded('pdo_sqlite')) {
        try {
            $sqliteVer = (string)(new PDO('sqlite::memory:'))->query('select sqlite_version()')->fetchColumn();
        } catch (Throwable $t) {
        }
    }
    $curlSsl = function_exists('curl_version') && (((int)(curl_version()['features'] ?? 0)) & CURL_VERSION_SSL);
    $public  = data_dir_is_public(DATA_DIR);
    return [
        ['PHP 8.0 or newer', PHP_VERSION_ID >= 80000, true, 'Running ' . PHP_VERSION],
        ['PDO SQLite extension', extension_loaded('pdo_sqlite'), true, ''],
        ['SQLite 3.25 or newer', $sqliteVer !== '' && version_compare($sqliteVer, '3.25.0', '>='), true, $sqliteVer ? "Found $sqliteVer" : ''],
        ['cURL extension with HTTPS support', extension_loaded('curl') && $curlSsl, true, ''],
        ['DOM extension (HTML parsing)', class_exists('DOMDocument'), true, ''],
        ['Private data folder is writable', $dataOk, true, DATA_DIR],
        ['Data folder is outside the public web root', !$public, false,
            $public ? 'It is inside the web root. Fine on Apache/IIS (protected by .htaccess/web.config), but on nginx add a deny rule or set PDLF_DATA_DIR.' : 'Good: database, config, logs and backups are not web-accessible.'],
        ['Connection is HTTPS', is_https(), false, is_https() ? '' : 'Strongly recommended: your password and session cookie travel over this connection.'],
        ['mbstring (legacy page encodings)', extension_loaded('mbstring'), false, 'Optional'],
        ['intl (internationalised domain names)', function_exists('idn_to_ascii'), false, 'Optional'],
    ];
}

if (!is_file(CONFIG_FILE)) {
    $error  = '';
    $checks = env_checks($DATA_DIR_OK);
    $blocked = false;
    foreach ($checks as $c) {
        if ($c[2] && !$c[1]) $blocked = true;
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'install') {
        $u  = trim((string)($_POST['u'] ?? ''));
        $p  = (string)($_POST['p'] ?? '');
        $pc = (string)($_POST['p_confirm'] ?? '');
        if (!csrf_ok()) {
            $error = 'Session expired. Reload the page and try again.';
        } elseif ($blocked) {
            $error = 'Fix the failed requirements above before installing.';
        } elseif (!preg_match('/^[A-Za-z0-9._@-]{3,64}$/', $u)) {
            $error = 'Username must be 3–64 characters: letters, digits and . _ @ -';
        } elseif (strlen($p) < 10) {
            $error = 'Password must be at least 10 characters.';
        } elseif (strcasecmp($p, $u) === 0) {
            $error = 'Password must differ from the username.';
        } elseif ($p !== $pc) {
            $error = 'Passwords do not match.';
        } else {
            $cfg = [
                'user'                => $u,
                'pass_hash'           => password_hash($p, PASSWORD_DEFAULT),
                'db_file'             => 'pdlf-' . bin2hex(random_bytes(8)) . '.sqlite',
                'allow_private_hosts' => false,
                'ca_bundle'           => null,
                'limits'              => [],
                'created'             => time(),
            ];
            $fh = @fopen(CONFIG_FILE, 'x');          // 'x' = fail if someone else installed meanwhile
            if ($fh === false) {
                $error = 'Could not create the configuration file (already installed, or folder not writable).';
            } else {
                fwrite($fh, "<?php\n// PDLF configuration — keep private.\nreturn " . var_export($cfg, true) . ";\n");
                fclose($fh);
                @chmod(CONFIG_FILE, 0600);
                plog('INFO', 'Installation completed');
                reset_session();
                header('Location: ' . self_url());
                exit;
            }
        }
    }
    page_head('PDLF Setup');
    ?>
<div class="narrow card">
  <h2>PDLF setup</h2>
  <p class="muted small">Environment check, then create the one administrator account that locks this tool.</p>
  <table class="checks">
    <?php foreach ($checks as [$label, $ok, $required, $note]): ?>
      <tr>
        <td class="<?= $ok ? 'okc' : ($required ? 'badc' : 'warnc') ?>"><?= $ok ? '✔' : ($required ? '✖' : '!') ?></td>
        <td><?= e($label) ?><?php if ($note !== ''): ?><br><span class="muted small"><?= e($note) ?></span><?php endif; ?></td>
      </tr>
    <?php endforeach; ?>
  </table>
  <?php if ($error): ?><div class="banner err"><?= e($error) ?></div><?php endif; ?>
  <form method="post" autocomplete="off">
    <input type="hidden" name="action" value="install">
    <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">
    <label for="u">Administrator username</label>
    <input id="u" type="text" name="u" required autofocus autocomplete="username" minlength="3" maxlength="64">
    <label for="p">Password (min. 10 characters)</label>
    <input id="p" type="password" name="p" required autocomplete="new-password" minlength="10">
    <label for="pc">Confirm password</label>
    <input id="pc" type="password" name="p_confirm" required autocomplete="new-password" minlength="10">
    <p><button type="submit" <?= $blocked ? 'disabled' : '' ?>>Create account &amp; finish setup</button></p>
  </form>
</div>
<?php
    page_foot();
    exit;
}

$CONFIG = require CONFIG_FILE;
$CONFIG = (is_array($CONFIG) ? $CONFIG : []) + [
    'user' => '', 'pass_hash' => '', 'db_file' => 'pdlf.sqlite',
    'allow_private_hosts' => false, 'ca_bundle' => null, 'limits' => [],
];

function cfg(string $k)
{
    return $GLOBALS['CONFIG'][$k] ?? null;
}

function limit(string $k)
{
    $l = cfg('limits');
    return is_array($l) && array_key_exists($k, $l) ? $l[$k] : DEFAULT_LIMITS[$k];
}

// ============================================================================
// URL TOOLS: resolve, normalise, scope
// ============================================================================
function norm_component(string $s): string
{
    // Upper-case percent escapes, decode unreserved characters, encode everything illegal (UTF-8 bytes included).
    return preg_replace_callback(
        '/%([0-9A-Fa-f]{2})|%|[^A-Za-z0-9\-._~!$&\'()*+,;=:@\/?%]/',
        static function (array $m): string {
            if (isset($m[1]) && $m[1] !== '') {
                $chr = chr((int)hexdec($m[1]));
                return preg_match('/^[A-Za-z0-9\-._~]$/', $chr) ? $chr : '%' . strtoupper($m[1]);
            }
            return '%' . strtoupper(bin2hex($m[0]));
        },
        $s
    ) ?? $s;
}

function remove_dot_segments(string $path): string
{
    $in  = explode('/', $path);
    $out = [];
    $n   = count($in);
    foreach ($in as $i => $seg) {
        if ($seg === '..') {
            if (count($out) > 1) array_pop($out);
            if ($i === $n - 1) $out[] = '';
        } elseif ($seg === '.') {
            if ($i === $n - 1) $out[] = '';
        } else {
            $out[] = $seg;
        }
    }
    $r = implode('/', $out);
    if ($r === '') return '/';
    return $r[0] === '/' ? $r : '/' . $r;
}

function strip_tracking(string $q): string
{
    $keep = [];
    foreach (explode('&', $q) as $kv) {
        if ($kv === '') continue;
        $name = strtolower(urldecode(explode('=', $kv, 2)[0]));
        if (str_starts_with($name, 'utm_') || in_array($name, TRACKING_PARAMS, true)) continue;
        $keep[] = $kv;
    }
    return implode('&', $keep);
}

/** Canonical form used for de-duplication and for every request we make. */
function normalize_url(string $url, bool $stripTracking = true): ?string
{
    $url = preg_replace('/[\t\r\n]+/', '', trim($url)) ?? '';
    if ($url === '' || strlen($url) > (int)limit('max_url_length')) return null;
    if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $url)) return null;
    $url = explode('#', $url, 2)[0];

    $p = @parse_url($url);
    if ($p === false || !isset($p['scheme'], $p['host'])) return null;
    $scheme = strtolower($p['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') return null;
    if (isset($p['user']) || isset($p['pass'])) return null;       // credentials in URLs: never

    $host = strtolower(rtrim(trim($p['host'], '[]'), '.'));
    if ($host === '') return null;
    $v6 = str_contains($host, ':');
    if (!$v6) {
        if (preg_match('/[^\x00-\x7F]/', $host)) {
            if (!function_exists('idn_to_ascii')) return null;
            $a = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($a === false) return null;
            $host = strtolower($a);
        }
        if (!preg_match('/^[a-z0-9._-]+$/', $host)) return null;
    }

    $port = $p['port'] ?? null;
    if ($port !== null && ($port < 1 || $port > 65535)) return null;
    if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) $port = null;

    $path = ($p['path'] ?? '') === '' ? '/' : $p['path'];
    $path = remove_dot_segments(norm_component($path));

    $q = '';
    if (isset($p['query']) && $p['query'] !== '') {
        $q = norm_component($p['query']);
        if ($stripTracking) $q = strip_tracking($q);
    }
    return $scheme . '://' . ($v6 ? "[$host]" : $host) . ($port ? ":$port" : '') . $path . ($q !== '' ? '?' . $q : '');
}

/** RFC 3986 reference resolution. Returns null for non-http(s) references. */
function resolve_url(string $base, string $ref): ?string
{
    $ref = preg_replace('/[\t\r\n]+/', '', trim($ref)) ?? '';
    if (preg_match('#^[A-Za-z][A-Za-z0-9+.\-]*:#', $ref)) {
        return preg_match('#^https?://#i', $ref) ? $ref : null;     // mailto:, tel:, javascript:, data: ...
    }
    $b = @parse_url($base);
    if (!$b || empty($b['scheme']) || empty($b['host'])) return null;
    $auth = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
    if (str_starts_with($ref, '//')) return $b['scheme'] . ':' . $ref;

    $pos = strpos($ref, '#');
    if ($pos !== false) $ref = substr($ref, 0, $pos);
    if ($ref === '') return $auth . ($b['path'] ?? '/') . (isset($b['query']) ? '?' . $b['query'] : '');

    $q = null;
    $pos = strpos($ref, '?');
    if ($pos !== false) {
        $q    = substr($ref, $pos + 1);
        $path = substr($ref, 0, $pos);
    } else {
        $path = $ref;
    }
    if ($path === '') {
        $np = $b['path'] ?? '/';
    } elseif ($path[0] === '/') {
        $np = $path;
    } else {
        $bp  = ($b['path'] ?? '') === '' ? '/' : $b['path'];
        $np  = substr($bp, 0, (int)strrpos($bp, '/') + 1) . $path;
    }
    return $auth . remove_dot_segments($np) . ($q !== null ? '?' . $q : '');
}

function host_key(string $h): string
{
    $h = strtolower(rtrim(trim($h, '[]'), '.'));
    return str_starts_with($h, 'www.') ? substr($h, 4) : $h;
}

function registrable_domain(string $host): string
{
    $h = host_key($host);
    if (filter_var($h, FILTER_VALIDATE_IP)) return $h;
    $l = explode('.', $h);
    if (count($l) <= 2) return $h;
    $two = implode('.', array_slice($l, -2));
    return in_array($two, SECOND_LEVEL_SUFFIXES, true) ? implode('.', array_slice($l, -3)) : $two;
}

function host_in_scope(string $host, array $opt): bool
{
    $hk    = host_key($host);
    $start = host_key((string)parse_url($opt['start_url'], PHP_URL_HOST));
    if ($hk === $start) return true;
    switch ($opt['scope']) {
        case 'selected':
            return in_array($hk, $opt['hosts'], true);
        case 'all':
            return str_ends_with($hk, '.' . $start);
        default:
            return false;
    }
}

function url_ext(string $url): string
{
    return strtolower(pathinfo((string)parse_url($url, PHP_URL_PATH), PATHINFO_EXTENSION));
}

/** null = ignore this link, 1 = check + crawl, 0 = check only. */
function discover_class(string $url, string $kind, array $opt): ?int
{
    $ext = url_ext($url);
    if ($ext !== '' && in_array($ext, $opt['skip_check'], true)) return null;
    $in = host_in_scope((string)parse_url($url, PHP_URL_HOST), $opt);
    if (!$in && empty($opt['check_external'])) return null;
    return ($kind === 'a' && $in && !in_array($ext, $opt['skip_crawl'], true)) ? 1 : 0;
}

// ============================================================================
// HTML PARSING
// ============================================================================
function html_to_utf8(string $html, ?string $contentType): string
{
    $cs = null;
    if ($contentType && preg_match('/charset\s*=\s*"?([\w.:-]+)/i', $contentType, $m)) {
        $cs = $m[1];
    } elseif (preg_match('/<meta[^>]+charset\s*=\s*["\']?([\w.:-]+)/i', substr($html, 0, 4096), $m)) {
        $cs = $m[1];
    }
    if ($cs && !in_array(strtolower($cs), ['utf-8', 'utf8', 'us-ascii', 'ascii'], true) && function_exists('mb_convert_encoding')) {
        try {
            $c = mb_convert_encoding($html, 'UTF-8', $cs);
            if (is_string($c)) return $c;
        } catch (Throwable $t) {
        }
    }
    return $html;
}

/** @return array<int, array{url:string, kind:string}>  kind: 'a' = page link, 'res' = resource */
function extract_links(string $html, string $pageUrl, ?string $contentType, bool $resources): array
{
    $html = html_to_utf8($html, $contentType);
    $prev = libxml_use_internal_errors(true);
    $dom  = new DOMDocument();
    $ok   = $dom->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET | LIBXML_COMPACT);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
    if (!$ok) return [];

    $base = $pageUrl;                                    // <base href> changes how relative URLs resolve
    foreach ($dom->getElementsByTagName('base') as $b) {
        $h = trim($b->getAttribute('href'));
        if ($h === '') continue;
        $r = resolve_url($pageUrl, $h);
        if ($r !== null && ($n = normalize_url($r, false)) !== null) $base = $n;
        break;
    }

    $map = ['a' => ['href'], 'area' => ['href']];
    if ($resources) {
        $map += ['img' => ['src'], 'script' => ['src'], 'link' => ['href'], 'iframe' => ['src'], 'source' => ['src'],
                 'video' => ['src', 'poster'], 'audio' => ['src'], 'embed' => ['src'], 'track' => ['src'], 'object' => ['data']];
    }
    $cap = (int)limit('max_links_page');
    $out = [];
    foreach ($map as $tag => $attrs) {
        $kind = ($tag === 'a' || $tag === 'area') ? 'a' : 'res';
        foreach ($dom->getElementsByTagName($tag) as $node) {
            if ($tag === 'link' && preg_match('/\b(dns-prefetch|preconnect)\b/i', $node->getAttribute('rel'))) continue;
            foreach ($attrs as $attr) {
                $v = trim($node->getAttribute($attr));
                if ($v === '' || $v[0] === '#') continue;
                $abs = resolve_url($base, $v);
                $n   = $abs === null ? null : normalize_url($abs, true);
                if ($n === null) continue;
                if (!isset($out[$n]) || $kind === 'a') $out[$n] = $kind;
                if (count($out) >= $cap) break 3;
            }
        }
    }
    $list = [];
    foreach ($out as $u => $k) $list[] = ['url' => $u, 'kind' => $k];
    return $list;
}

// ============================================================================
// SSRF GUARD
// ============================================================================
function cidr_match(string $bin, string $cidr): bool
{
    [$net, $bits] = explode('/', $cidr);
    $nb = inet_pton($net);
    if ($nb === false || strlen($nb) !== strlen($bin)) return false;
    $bits = (int)$bits;
    $full = intdiv($bits, 8);
    $rem  = $bits % 8;
    if ($full > 0 && substr($bin, 0, $full) !== substr($nb, 0, $full)) return false;
    if ($rem > 0) {
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        if ((ord($bin[$full]) & $mask) !== (ord($nb[$full]) & $mask)) return false;
    }
    return true;
}

function public_v4_bin(string $bin): bool
{
    foreach (BLOCKED_V4 as $c) {
        if (cidr_match($bin, $c)) return false;
    }
    return true;
}

function is_public_ip(string $ip): bool
{
    $bin = @inet_pton($ip);
    if ($bin === false) return false;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return false;
    if (strlen($bin) === 4) return public_v4_bin($bin);

    // IPv6 forms that embed an IPv4 address: judge the embedded address.
    if (cidr_match($bin, '::ffff:0:0/96') || cidr_match($bin, '64:ff9b::/96') || cidr_match($bin, '::/96')) {
        return public_v4_bin(substr($bin, 12, 4));
    }
    if (cidr_match($bin, '2002::/16')) {
        return public_v4_bin(substr($bin, 2, 4));
    }
    foreach (BLOCKED_V6 as $c) {
        if (cidr_match($bin, $c)) return false;
    }
    return true;
}

function resolve_host(string $host): array
{
    static $cache = [];
    if (isset($cache[$host])) return $cache[$host];
    $v4 = $v6 = [];
    if (function_exists('dns_get_record')) {
        $recs = @dns_get_record($host . '.', DNS_A | DNS_AAAA);
        foreach (is_array($recs) ? $recs : [] as $r) {
            if (!empty($r['ip'])) $v4[] = $r['ip'];
            elseif (!empty($r['ipv6'])) $v6[] = $r['ipv6'];
        }
    }
    if (!$v4 && !$v6) {
        $g = @gethostbynamel($host);
        if (is_array($g)) $v4 = $g;
    }
    return $cache[$host] = array_slice(array_values(array_unique(array_merge($v4, $v6))), 0, 8);
}

/**
 * Validate a URL BEFORE any request. Returns ['ok'=>true,'ips'=>[...]] or
 * ['ok'=>false,'kind'=>'blocked'|'dns','error'=>string].
 * The validated IPs are pinned into cURL (CURLOPT_RESOLVE), so a hostile DNS server
 * cannot answer "public" here and "127.0.0.1" a moment later (DNS rebinding).
 */
function ssrf_check(string $url): array
{
    $block = static fn(string $m): array => ['ok' => false, 'kind' => 'blocked', 'error' => 'Blocked: ' . $m];
    $p = @parse_url($url);
    if (!$p || empty($p['host']) || empty($p['scheme'])) return $block('invalid URL');
    $scheme = strtolower($p['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') return $block('only http and https are allowed');
    if (isset($p['user']) || isset($p['pass'])) return $block('credentials in URL');

    $allowPrivate = (bool)cfg('allow_private_hosts');
    $port = (int)($p['port'] ?? ($scheme === 'https' ? 443 : 80));
    if (!$allowPrivate && !in_array($port, (array)limit('allowed_ports'), true)) return $block("port $port is not allowed");

    $host = strtolower(rtrim(trim($p['host'], '[]'), '.'));
    if ($host === '') return $block('empty host');
    $isIp = filter_var($host, FILTER_VALIDATE_IP) !== false;

    if (!$allowPrivate) {
        if ($host === 'localhost' || preg_match('/\.(localhost|local|internal|localdomain|home\.arpa|intranet|corp|lan)$/', $host)) {
            return $block('local host name');
        }
        if (!$isIp && preg_match('/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$/i', $host)) {
            return $block('obfuscated IP address');          // 2130706433, 0x7f.1, 017700000001 ...
        }
    }
    $ips = $isIp ? [$host] : resolve_host($host);
    if (!$ips) return ['ok' => false, 'kind' => 'dns', 'error' => 'DNS lookup failed (domain not found)'];
    if (!$allowPrivate) {
        foreach ($ips as $ip) {
            if (!is_public_ip($ip)) return $block("$host resolves to a private or reserved address ($ip)");
        }
    }
    return ['ok' => true, 'ips' => $ips, 'host' => $host, 'port' => $port];
}

// ============================================================================
// HTTP ENGINE: one hop, redirects, link checking, classification
// ============================================================================
function curl_hop(string $method, string $url, array $ips, float $timeout, int $maxBytes, bool $htmlOnly): array
{
    $p    = parse_url($url);
    $port = (int)($p['port'] ?? (($p['scheme'] ?? '') === 'https' ? 443 : 80));
    $host = strtolower(trim((string)$p['host'], '[]'));
    $pins = array_map(static fn($ip) => str_contains($ip, ':') ? "[$ip]" : $ip, $ips);

    $hdr = [];
    $body = '';
    $truncated = false;
    $lim = $maxBytes;
    $first = true;
    $timeoutS = max(1, (int)ceil($timeout));

    $ch = curl_init();
    $opts = [
        CURLOPT_URL            => $url,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT        => $timeoutS,
        CURLOPT_CONNECTTIMEOUT => min((int)limit('connect_timeout'), $timeoutS),
        CURLOPT_USERAGENT      => USER_AGENT,
        CURLOPT_SSL_VERIFYPEER => true,                 // certificates are ALWAYS verified
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROXY          => '',                   // ignore proxy env vars: they would bypass the IP pinning
        CURLOPT_ENCODING       => '',
        CURLOPT_HTTPHEADER     => ['Accept: text/html,application/xhtml+xml,*/*;q=0.8', 'Accept-Language: en'],
        CURLOPT_RESOLVE        => ["$host:$port:" . implode(',', $pins)],
        CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$hdr): int {
            $len = strlen($line);
            if (str_starts_with($line, 'HTTP/')) { $hdr = []; return $len; }
            $pos = strpos($line, ':');
            if ($pos !== false) {
                $name = strtolower(trim(substr($line, 0, $pos)));
                if (!isset($hdr[$name])) $hdr[$name] = trim(substr($line, $pos + 1));
            }
            return $len;
        },
        CURLOPT_WRITEFUNCTION  => static function ($c, string $chunk) use (&$body, &$truncated, &$lim, &$first, &$hdr, $htmlOnly): int {
            if ($first) {
                $first = false;
                $ct = $hdr['content-type'] ?? '';
                if ($htmlOnly && $ct !== '' && !preg_match('#text/html|application/xhtml#i', $ct)) $lim = 1;   // not a page: stop early
            }
            $len = strlen($chunk);
            if (strlen($body) + $len > $lim) {
                $body .= substr($chunk, 0, max(0, $lim - strlen($body)));
                $truncated = true;
                return 0;                                  // abort the transfer: response size is capped
            }
            $body .= $chunk;
            return $len;
        },
    ];
    if ($method === 'HEAD') $opts[CURLOPT_NOBODY] = true;
    else $opts[CURLOPT_HTTPGET] = true;
    if ($ca = cfg('ca_bundle')) $opts[CURLOPT_CAINFO] = (string)$ca;
    curl_setopt_array($ch, $opts);

    curl_exec($ch);
    $errno = curl_errno($ch);
    $err   = curl_error($ch);
    $code  = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $ms    = (int)round(((float)curl_getinfo($ch, CURLINFO_TOTAL_TIME)) * 1000);
    curl_close($ch);

    if ($errno === 23 && $truncated) { $errno = 0; $err = ''; }   // our own deliberate abort
    return ['code' => $code, 'errno' => $errno, 'error' => $err, 'headers' => $hdr, 'body' => $body, 'truncated' => $truncated, 'ms' => $ms];
}

function result_base(string $url): array
{
    return ['code' => 0, 'errno' => 0, 'error' => null, 'blocked' => null, 'loop' => false, 'too_many' => false,
            'final_url' => $url, 'chain' => [], 'ct' => null, 'body' => '', 'ms' => 0];
}

/** Follows redirects manually so that EVERY hop is SSRF-checked, loops are detected and limits apply. */
function fetch_follow(string $method, string $url, float $timeout, int $maxBytes, float $deadline, bool $htmlOnly = false): array
{
    $res  = result_base($url);
    $seen = [];
    $cur  = $url;
    $max  = (int)limit('max_redirects');
    for ($hop = 0; ; $hop++) {
        if (isset($seen[$cur])) { $res['loop'] = true; $res['final_url'] = $cur; return $res; }
        $seen[$cur] = true;

        $chk = ssrf_check($cur);
        if (!$chk['ok']) {
            $res['final_url'] = $cur;
            if ($chk['kind'] === 'dns') { $res['errno'] = 6; $res['error'] = $chk['error']; }
            else $res['blocked'] = $chk['error'] . ($hop > 0 ? ' (redirect target)' : '');
            return $res;
        }
        $remaining = $deadline - microtime(true);
        if ($remaining < 1) { $res['errno'] = 28; $res['error'] = 'Time limit for this link exceeded'; $res['final_url'] = $cur; return $res; }

        $r = curl_hop($method, $cur, $chk['ips'], min($timeout, $remaining), $maxBytes, $htmlOnly);
        $res['ms'] += $r['ms'];
        $res['final_url'] = $cur;
        $res['code']  = $r['code'];
        $res['errno'] = $r['errno'];
        $res['error'] = $r['errno'] ? ('curl: ' . $r['error']) : null;
        $res['ct']    = $r['headers']['content-type'] ?? null;
        $res['body']  = $r['body'];

        if ($r['errno'] === 0 && in_array($r['code'], [301, 302, 303, 307, 308], true)) {
            $loc = (string)($r['headers']['location'] ?? '');
            if ($loc === '') { $res['error'] = "HTTP {$r['code']} redirect without a Location header"; return $res; }
            $abs  = resolve_url($cur, $loc);
            $next = $abs === null ? null : normalize_url($abs, false);
            if ($next === null) { $res['error'] = 'Redirect to an invalid or unsupported URL'; return $res; }
            $res['chain'][] = ['code' => $r['code'], 'to' => $next];
            if ($hop >= $max) { $res['too_many'] = true; $res['final_url'] = $next; return $res; }
            $cur = $next;
            continue;
        }
        return $res;
    }
}

function is_transient(array $r): bool
{
    return !$r['blocked'] && !$r['loop'] && !$r['too_many']
        && (in_array($r['errno'], [28, 56, 52, 18], true) || in_array($r['code'], [500, 502, 504], true));
}

function head_unreliable(array $r): bool
{
    if ($r['blocked'] || $r['loop'] || $r['too_many']) return false;      // a GET would not change that
    if ($r['errno'] === 6) return false;                                  // no DNS: nothing to retry
    return $r['errno'] !== 0 || $r['code'] === 0 || $r['code'] >= 400 || ($r['code'] >= 300 && $r['error'] !== null);
}

function classify(array $r): array
{
    if ($r['blocked']) return ['unverified', $r['blocked']];
    if ($r['loop']) return ['broken', 'Redirect loop'];
    if ($r['too_many']) return ['broken', 'Too many redirects (more than ' . limit('max_redirects') . ')'];
    if ($r['errno'] !== 0) {
        $msg = (string)($r['error'] ?? 'Network error');
        switch ($r['errno']) {
            case 6:  return ['broken', $msg];                                         // DNS
            case 51: case 60: case 83: return ['broken', 'Invalid TLS certificate — ' . $msg];
            case 28: return ['unverified', $r['error'] ?? 'Timed out'];
            default: return ['unverified', $msg];                                     // refused, reset, TLS handshake ...
        }
    }
    $c = $r['code'];
    if ($c >= 200 && $c < 300) return ['working', null];
    if ($c >= 300 && $c < 400) return ['unverified', $r['error'] ?? "HTTP $c (no usable redirect)"];
    if ($c === 404 || $c === 410) return ['broken', "HTTP $c"];
    if ($c >= 400 && $c < 500) return ['unverified', "HTTP $c (access restricted, rate limited or bot-blocked)"];
    if ($c === 503) return ['unverified', 'HTTP 503 (temporarily unavailable)'];
    if ($c >= 500) return ['broken', "HTTP $c server error"];
    return ['unverified', 'No valid HTTP response'];
}

function check_link(string $url, bool $crawl, float $timeout): array
{
    $deadline = microtime(true) + (float)limit('link_seconds');
    if ($crawl) {
        $r = fetch_follow('GET', $url, $timeout, (int)limit('max_html_bytes'), $deadline, true);
        if (is_transient($r) && microtime(true) + $timeout < $deadline) {
            usleep(600000);
            $r = fetch_follow('GET', $url, $timeout, (int)limit('max_html_bytes'), $deadline, true);
        }
    } else {
        $r = fetch_follow('HEAD', $url, $timeout, 0, $deadline);
        if (head_unreliable($r)) {                                     // HEAD unsupported or lying: ask with GET
            $g = fetch_follow('GET', $url, $timeout, 1, $deadline);
            if ($g['code'] > 0 || $r['code'] === 0) $r = $g;
        }
        if (is_transient($r) && microtime(true) + $timeout < $deadline) {
            usleep(600000);
            $r = fetch_follow('GET', $url, $timeout, 1, $deadline);
        }
    }
    [$status, $why] = classify($r);
    $r['status'] = $status;
    $r['why']    = $why;
    return $r;
}

// ============================================================================
// DATABASE (SQLite)
// ============================================================================
function db(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;
    $file = DATA_DIR . '/' . basename((string)(cfg('db_file') ?: 'pdlf.sqlite'));
    $new  = !is_file($file);
    $pdo  = new PDO('sqlite:' . $file, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA busy_timeout = 8000');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA synchronous = NORMAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    if ($new) @chmod($file, 0600);
    migrate($pdo);
    return $pdo;
}

function migrate(PDO $pdo): void
{
    if ((int)$pdo->query('PRAGMA user_version')->fetchColumn() >= 2) return;
    $pdo->exec('BEGIN');
    $pdo->exec(<<<'SQL'
        CREATE TABLE IF NOT EXISTS scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            start_url  TEXT    NOT NULL,
            options    TEXT    NOT NULL,
            status     TEXT    NOT NULL DEFAULT 'running',     -- running | stopped | completed
            truncated  INTEGER NOT NULL DEFAULT 0,             -- 1 = "Max links" cut discovery short
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            finished_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS links (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            url            TEXT    NOT NULL,
            crawl          INTEGER NOT NULL DEFAULT 0,         -- 1 = fetch the page and extract links
            status         TEXT    NOT NULL DEFAULT 'pending', -- pending | working | broken | unverified
            http_code      INTEGER,
            error          TEXT,
            final_url      TEXT,
            redirect_count INTEGER NOT NULL DEFAULT 0,
            redirect_chain TEXT,                               -- JSON [{"code":301,"to":"..."}]
            content_type   TEXT,
            response_ms    INTEGER,
            attempts       INTEGER NOT NULL DEFAULT 0,
            checked_at     INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_links_scan_url ON links(scan_id, url);
        CREATE INDEX IF NOT EXISTS ix_links_scan_status ON links(scan_id, status);
        CREATE TABLE IF NOT EXISTS link_sources (
            link_id   INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
            source_id INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
            PRIMARY KEY (link_id, source_id)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS ix_sources_source ON link_sources(source_id);
        CREATE TABLE IF NOT EXISTS locks (name TEXT PRIMARY KEY, token TEXT, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, ts INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_login_ip ON login_attempts(ip, ts);
    SQL);
    $pdo->exec('PRAGMA user_version = 2');
    $pdo->exec('COMMIT');
}

// ---- one batch at a time ---------------------------------------------------
function lock_acquire(int $scanId, int $ttl): ?string
{
    $token = $scanId . ':' . bin2hex(random_bytes(8));
    $now   = time();
    $st = db()->prepare(
        "INSERT INTO locks(name, token, expires) VALUES('batch', ?, ?)
         ON CONFLICT(name) DO UPDATE SET token = excluded.token, expires = excluded.expires
         WHERE locks.expires < ?"
    );
    $st->execute([$token, $now + $ttl, $now]);
    return $st->rowCount() === 1 ? $token : null;
}

function lock_release(string $token): void
{
    try {
        db()->prepare("UPDATE locks SET expires = 0 WHERE name = 'batch' AND token = ?")->execute([$token]);
    } catch (Throwable $t) {
    }
}

function locked_scan(): ?int
{
    $st = db()->prepare("SELECT token FROM locks WHERE name = 'batch' AND expires > ?");
    $st->execute([time()]);
    $t = $st->fetchColumn();
    return $t === false ? null : (int)explode(':', (string)$t)[0];
}

// ============================================================================
// AUTHENTICATION
// ============================================================================
function is_authenticated(): bool
{
    if (empty($_SESSION['pdlf_user'])) return false;
    $now = time();
    if ($now - (int)($_SESSION['last_activity'] ?? 0) > 1800 || $now - (int)($_SESSION['login_at'] ?? 0) > 28800) {
        reset_session();                                   // 30 min idle or 8 h absolute
        return false;
    }
    $_SESSION['last_activity'] = $now;
    return true;
}

function login_page(string $error = ''): void
{
    page_head('PDLF Sign in');
    ?>
<div class="narrow card">
  <h2>🔗 PDLF sign in</h2>
  <?php if ($error): ?><div class="banner err"><?= e($error) ?></div><?php endif; ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">
    <input type="hidden" name="pdlf_login" value="1">
    <label for="u">Username</label>
    <input id="u" type="text" name="u" required autofocus autocomplete="username">
    <label for="p">Password</label>
    <input id="p" type="password" name="p" required autocomplete="current-password">
    <p><button type="submit">Sign in</button></p>
  </form>
</div>
<?php
    page_foot();
    exit;
}

function handle_login(): void
{
    global $CONFIG;
    $ip  = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $now = time();
    $pdo = db();
    $pdo->prepare('DELETE FROM login_attempts WHERE ts < ?')->execute([$now - 86400]);

    if (!csrf_ok()) login_page('Session expired. Please try again.');
    $st = $pdo->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND ts > ?');
    $st->execute([$ip, $now - 900]);
    if ((int)$st->fetchColumn() >= 5) {
        plog('WARN', 'Login throttled');
        login_page('Too many failed attempts. Try again in 15 minutes.');
    }

    $u = (string)($_POST['u'] ?? '');
    $p = (string)($_POST['p'] ?? '');
    $hash = (string)$CONFIG['pass_hash'];
    $userOk = hash_equals((string)$CONFIG['user'], $u);
    $passOk = password_verify($p, $hash);                  // always evaluated: no username-timing leak
    if ($userOk && $passOk) {
        $pdo->prepare('DELETE FROM login_attempts WHERE ip = ?')->execute([$ip]);
        session_regenerate_id(true);
        $_SESSION['pdlf_user']      = $u;
        $_SESSION['login_at']       = $now;
        $_SESSION['last_activity']  = $now;
        $_SESSION['csrf_token']     = bin2hex(random_bytes(32));
        if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            $CONFIG['pass_hash'] = password_hash($p, PASSWORD_DEFAULT);
            save_config();
        }
        plog('INFO', 'Login OK');
        header('Location: ' . self_url());
        exit;
    }
    $pdo->prepare('INSERT INTO login_attempts(ip, ts) VALUES(?, ?)')->execute([$ip, $now]);
    plog('WARN', 'Login failed');
    login_page('Invalid username or password.');
}

function save_config(): void
{
    global $CONFIG;
    $tmp = CONFIG_FILE . '.tmp';
    if (@file_put_contents($tmp, "<?php\n// PDLF configuration — keep private.\nreturn " . var_export($CONFIG, true) . ";\n", LOCK_EX) !== false) {
        @chmod($tmp, 0600);
        @rename($tmp, CONFIG_FILE);
    }
}

// ============================================================================
// SCAN HELPERS
// ============================================================================
function json_out(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    exit;
}

function fail(string $msg, int $status = 200): void
{
    json_out(['ok' => false, 'error' => $msg], $status);
}

function parse_list(string $s): array
{
    return array_values(array_filter(preg_split('/[,\s;]+/', strtolower($s)) ?: [], static fn($x) => $x !== ''));
}

function parse_ext_list(string $s): array
{
    $out = [];
    foreach (parse_list($s) as $x) {
        $x = ltrim($x, '.*');
        if (preg_match('/^[a-z0-9]{1,10}$/', $x)) $out[$x] = true;
    }
    return array_keys($out);
}

function parse_hosts(string $s): array
{
    $out = [];
    foreach (parse_list($s) as $x) {
        if (str_contains($x, '/')) $x = (string)parse_url(str_contains($x, '://') ? $x : "http://$x", PHP_URL_HOST);
        $x = host_key($x);
        if ($x !== '' && preg_match('/^[a-z0-9.-]+$/', $x)) $out[$x] = true;
    }
    return array_slice(array_keys($out), 0, 200);
}

function get_scan(int $id): ?array
{
    $st = db()->prepare('SELECT * FROM scans WHERE id = ?');
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row) return null;
    $row['opt'] = json_decode((string)$row['options'], true) ?: [];
    return $row;
}

function scan_counts(int $id): array
{
    $c = ['pending' => 0, 'working' => 0, 'broken' => 0, 'unverified' => 0];
    $st = db()->prepare('SELECT status, COUNT(*) c FROM links WHERE scan_id = ? GROUP BY status');
    $st->execute([$id]);
    foreach ($st->fetchAll() as $r) $c[$r['status']] = (int)$r['c'];
    $c['total']   = array_sum($c);
    $c['checked'] = $c['total'] - $c['pending'];
    return $c;
}

function scan_public(array $s): array
{
    return [
        'id' => (int)$s['id'], 'start_url' => $s['start_url'], 'status' => $s['status'], 'truncated' => (int)$s['truncated'],
        'created_at' => (int)$s['created_at'], 'finished_at' => $s['finished_at'] !== null ? (int)$s['finished_at'] : null,
        'scope' => $s['opt']['scope'] ?? 'single', 'max_links' => $s['opt']['max_links'] ?? null,
    ];
}

function make_backup(): void
{
    try {
        $dir = DATA_DIR . '/backups';
        if (!is_dir($dir)) return;
        $file = $dir . '/pdlf-' . gmdate('Ymd-His') . '.sqlite';
        db()->exec('VACUUM INTO ' . db()->quote($file));
        @chmod($file, 0600);
        $all = glob($dir . '/pdlf-*.sqlite') ?: [];
        rsort($all);
        foreach (array_slice($all, (int)limit('keep_backups')) as $old) @unlink($old);
    } catch (Throwable $t) {
        plog('WARN', 'Backup failed: ' . $t->getMessage());
    }
}

/** Store discovered links and remember on which page each was found. */
function record_links(int $scanId, int $sourceId, array $found, array $opt, int &$room, int &$truncated): int
{
    $pdo  = db();
    $sel  = $pdo->prepare('SELECT id FROM links WHERE scan_id = ? AND url = ?');
    $ins  = $pdo->prepare('INSERT INTO links(scan_id, url, crawl) VALUES(?, ?, ?)');
    $src  = $pdo->prepare('INSERT OR IGNORE INTO link_sources(link_id, source_id) VALUES(?, ?)');
    $new  = 0;
    foreach ($found as $f) {
        $crawl = discover_class($f['url'], $f['kind'], $opt);
        if ($crawl === null) continue;
        $sel->execute([$scanId, $f['url']]);
        $id = $sel->fetchColumn();
        if ($id === false) {
            if ($room <= 0) { $truncated = 1; continue; }
            $ins->execute([$scanId, $f['url'], $crawl]);
            $id = (int)$pdo->lastInsertId();
            $room--;
            $new++;
        }
        $src->execute([(int)$id, $sourceId]);
    }
    return $new;
}

function run_batch(int $scanId): array
{
    $scan = get_scan($scanId);
    if (!$scan) fail('Scan not found.');
    if ($scan['status'] === 'completed') {
        $c = scan_counts($scanId);
        return ['ok' => true, 'processed' => 0, 'discovered' => 0, 'counts' => $c, 'done' => true, 'notes' => [], 'last' => null];
    }
    if ($scan['status'] === 'stopped') fail('This scan is stopped. Resume it first.');

    ignore_user_abort(true);                               // finish writing results even if the browser goes away
    $budget = (int)limit('batch_seconds');
    $ttl    = $budget + (int)limit('link_seconds') + 25;
    @set_time_limit($ttl);

    $token = lock_acquire($scanId, $ttl);
    if ($token === null) {
        return ['ok' => true, 'busy' => true, 'counts' => scan_counts($scanId), 'done' => false];
    }
    register_shutdown_function('lock_release', $token);    // also runs after a fatal error / timeout

    $opt       = $scan['opt'];
    $timeout   = (float)($opt['timeout'] ?? limit('request_timeout'));
    $deadline  = microtime(true) + $budget;
    $processed = 0; $discovered = 0; $notes = []; $last = null;
    $truncated = (int)$scan['truncated'];
    $pdo       = db();

    try {
        $total = (int)$pdo->query('SELECT COUNT(*) FROM links WHERE scan_id = ' . $scanId)->fetchColumn();
        $room  = max(0, (int)$opt['max_links'] - $total);

        $next = $pdo->prepare("SELECT id, url, crawl, attempts FROM links WHERE scan_id = ? AND status = 'pending' ORDER BY id LIMIT 1");
        $bump = $pdo->prepare('UPDATE links SET attempts = attempts + 1 WHERE id = ?');
        $upd  = $pdo->prepare('UPDATE links SET status=?, http_code=?, error=?, final_url=?, redirect_count=?, redirect_chain=?, content_type=?, response_ms=?, checked_at=? WHERE id = ?');

        while (microtime(true) < $deadline) {
            $next->execute([$scanId]);
            $row = $next->fetch();
            if (!$row) break;
            $id = (int)$row['id'];
            $last = $row['url'];

            if ((int)$row['attempts'] >= 3) {              // this link keeps killing the worker: park it
                $upd->execute(['unverified', null, 'Skipped: the check failed repeatedly (crashed or timed out)', null, 0, null, null, null, time(), $id]);
                $processed++;
                continue;
            }
            $bump->execute([$id]);

            $r = check_link($row['url'], (bool)$row['crawl'], $timeout);
            $final = $r['final_url'] !== $row['url'] ? $r['final_url'] : null;

            $html = null;
            if ($r['status'] === 'working' && (int)$row['crawl'] === 1 && $r['body'] !== ''
                && host_in_scope((string)parse_url($r['final_url'], PHP_URL_HOST), $opt)) {
                $ct = (string)($r['ct'] ?? '');
                if ($ct === '' || preg_match('#text/html|application/xhtml#i', $ct)) $html = $r['body'];
            }

            $pdo->beginTransaction();
            try {
                $upd->execute([
                    $r['status'], $r['code'] ?: null, $r['why'], $final, count($r['chain']),
                    $r['chain'] ? json_encode($r['chain'], JSON_UNESCAPED_SLASHES) : null,
                    $r['ct'] ? substr((string)$r['ct'], 0, 120) : null, $r['ms'], time(), $id,
                ]);
                if ($html !== null) {
                    $found = extract_links($html, $r['final_url'], $r['ct'], !empty($opt['check_resources']));
                    $discovered += record_links($scanId, $id, $found, $opt, $room, $truncated);
                }
                $pdo->commit();
            } catch (Throwable $t) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                throw $t;
            }
            unset($html, $r['body']);
            $processed++;

            if ($r['status'] !== 'working' && count($notes) < 8) {
                $label = $r['status'] === 'broken' ? '✖ BROKEN' : '? UNVERIFIED';
                $notes[] = $label . ' ' . ($r['code'] ?: 'ERR') . ' ' . $row['url'] . ($r['why'] ? '  — ' . $r['why'] : '');
            }
        }

        $counts = scan_counts($scanId);
        $done   = $counts['pending'] === 0;
        $now    = time();
        if ($done) {
            $pdo->prepare("UPDATE scans SET status='completed', finished_at=?, updated_at=?, truncated=? WHERE id=?")->execute([$now, $now, $truncated, $scanId]);
            plog('INFO', "Scan #$scanId completed: {$counts['total']} links, {$counts['broken']} broken, {$counts['unverified']} unverified");
            make_backup();
        } else {
            $pdo->prepare('UPDATE scans SET updated_at=?, truncated=? WHERE id=?')->execute([$now, $truncated, $scanId]);
        }
    } finally {
        lock_release($token);
    }

    return ['ok' => true, 'processed' => $processed, 'discovered' => $discovered, 'counts' => $counts, 'done' => $done,
            'notes' => $notes, 'last' => $last, 'truncated' => $truncated];
}

function issues_filter(string $filter, string $q): array
{
    $w = "scan_id = ? AND status != 'pending'";
    $p = [];
    switch ($filter) {
        case 'broken':     $w .= " AND status = 'broken'"; break;
        case 'unverified': $w .= " AND status = 'unverified'"; break;
        case 'working':    $w .= " AND status = 'working'"; break;
        case 'redirected': $w .= ' AND redirect_count > 0'; break;
        case 'all':        break;
        default:           $w .= " AND status IN ('broken','unverified')";
    }
    if ($q !== '') {
        $w .= " AND url LIKE ? ESCAPE '\\'";
        $p[] = '%' . addcslashes($q, '%_\\') . '%';
    }
    return [$w, $p];
}

function attach_sources(array $rows, int $perLink): array
{
    if (!$rows) return $rows;
    $ids = array_column($rows, 'id');
    $in  = implode(',', array_fill(0, count($ids), '?'));
    $by  = [];
    $st = db()->prepare("SELECT link_id, url FROM (
            SELECT ls.link_id, s.url, ROW_NUMBER() OVER (PARTITION BY ls.link_id ORDER BY s.id) rn
            FROM link_sources ls JOIN links s ON s.id = ls.source_id WHERE ls.link_id IN ($in)
        ) WHERE rn <= $perLink");
    $st->execute($ids);
    foreach ($st->fetchAll() as $r) $by[(int)$r['link_id']][] = $r['url'];
    $cnt = [];
    $st = db()->prepare("SELECT link_id, COUNT(*) c FROM link_sources WHERE link_id IN ($in) GROUP BY link_id");
    $st->execute($ids);
    foreach ($st->fetchAll() as $r) $cnt[(int)$r['link_id']] = (int)$r['c'];
    foreach ($rows as &$r) {
        $r['sources']      = $by[(int)$r['id']] ?? [];
        $r['source_count'] = $cnt[(int)$r['id']] ?? 0;
        $r['chain']        = $r['redirect_chain'] ? (json_decode((string)$r['redirect_chain'], true) ?: []) : [];
        unset($r['redirect_chain']);
    }
    return $rows;
}

function csv_cell($v): string
{
    $s = (string)$v;
    return ($s !== '' && strpbrk($s[0], "=+-@\t\r") !== false) ? "'" . $s : $s;   // block spreadsheet formula injection
}

function export_csv(): void
{
    $id = (int)($_GET['scan'] ?? 0);
    if (!get_scan($id)) { http_response_code(404); exit('Scan not found'); }
    [$w, $p] = issues_filter((string)($_GET['filter'] ?? 'all'), '');
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="pdlf-scan-' . $id . '-' . gmdate('Ymd') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['status', 'http_code', 'url', 'final_url', 'redirects', 'redirect_chain', 'details', 'content_type', 'response_ms', 'found_on', 'checked_at (UTC)'], ',', '"', '');
    $st = db()->prepare("SELECT id, url, status, http_code, error, final_url, redirect_count, redirect_chain, content_type, response_ms, checked_at
                         FROM links WHERE $w AND id > ? ORDER BY id LIMIT 500");
    $after = 0;
    while (true) {
        $st->execute(array_merge([$id], $p, [$after]));
        $rows = $st->fetchAll();
        if (!$rows) break;
        foreach (attach_sources($rows, 3) as $r) {
            $chain = implode(' | ', array_map(static fn($h) => $h['code'] . ' ' . $h['to'], $r['chain']));
            fputcsv($out, array_map('csv_cell', [
                $r['status'], $r['http_code'], $r['url'], $r['final_url'], $r['redirect_count'], $chain, $r['error'],
                $r['content_type'], $r['response_ms'], implode(' | ', $r['sources']),
                $r['checked_at'] ? gmdate('Y-m-d H:i:s', (int)$r['checked_at']) : '',
            ]), ',', '"', '');
            $after = (int)$r['id'];
        }
    }
    fclose($out);
    exit;
}

// ============================================================================
// API (JSON, POST only, CSRF protected)
// ============================================================================
function handle_api(string $action): void
{
    if (!is_authenticated()) fail('Please sign in again.', 401);
    if (!csrf_ok()) fail('CSRF verification failed. Reload the page.', 403);
    session_write_close();                                  // don't hold the session lock during long batches

    set_exception_handler(static function (Throwable $t): void {
        plog('ERROR', get_class($t) . ': ' . $t->getMessage() . ' @ ' . basename($t->getFile()) . ':' . $t->getLine());
        fail('Internal error. See the PDLF log in the private data folder.', 500);
    });

    $sid = (int)($_POST['scan_id'] ?? 0);

    switch ($action) {
        case 'state': {
            $scans = db()->query('SELECT * FROM scans ORDER BY id DESC LIMIT 25')->fetchAll();
            $lock  = locked_scan();
            $out   = [];
            foreach ($scans as $s) {
                $s['opt'] = json_decode((string)$s['options'], true) ?: [];
                $row = scan_public($s);
                $row['counts'] = scan_counts((int)$s['id']);
                $row['active'] = $lock === (int)$s['id'];
                $out[] = $row;
            }
            json_out(['ok' => true, 'scans' => $out]);
        }

        case 'discover': {
            $start = normalize_url(preg_match('#^https?://#i', trim((string)($_POST['start_url'] ?? ''))) ? trim((string)$_POST['start_url']) : 'https://' . trim((string)($_POST['start_url'] ?? '')), false);
            if (!$start) fail('Enter a valid start URL first.');
            $r = fetch_follow('GET', $start, (float)limit('request_timeout'), (int)limit('max_html_bytes'), microtime(true) + (float)limit('link_seconds'), true);
            [$status, $why] = classify($r);
            if ($status !== 'working') fail('Could not read the start page: ' . ($why ?: 'unknown error'));
            $hosts = [];
            $base  = registrable_domain((string)parse_url($start, PHP_URL_HOST));
            $self  = host_key((string)parse_url($start, PHP_URL_HOST));
            foreach (extract_links($r['body'], $r['final_url'], $r['ct'], true) as $l) {
                $h = host_key((string)parse_url($l['url'], PHP_URL_HOST));
                if ($h !== $self && ($h === $base || str_ends_with($h, '.' . $base))) $hosts[$h] = true;
            }
            $list = array_keys($hosts);
            sort($list);
            json_out(['ok' => true, 'hosts' => array_slice($list, 0, 100), 'start_host' => $self]);
        }

        case 'start': {
            $raw = trim((string)($_POST['start_url'] ?? ''));
            if ($raw !== '' && !preg_match('#^https?://#i', $raw)) $raw = 'https://' . $raw;
            $start = normalize_url($raw, false);
            if (!$start) fail('Please enter a valid http(s) start URL.');
            $chk = ssrf_check($start);
            if (!$chk['ok']) fail($chk['kind'] === 'dns' ? 'The start URL’s domain could not be resolved.' : 'The start URL points to a private or unsafe destination. ' . $chk['error']);

            $scope = in_array($_POST['scope'] ?? '', ['single', 'selected', 'all'], true) ? $_POST['scope'] : 'single';
            $opt = [
                'start_url'       => $start,
                'scope'           => $scope,
                'hosts'           => $scope === 'selected' ? parse_hosts((string)($_POST['hosts'] ?? '')) : [],
                'max_links'       => max(1, min((int)limit('max_links_hard'), (int)($_POST['max_links'] ?? 500) ?: 500)),
                'timeout'         => max(3, min(30, (int)($_POST['timeout'] ?? 0) ?: (int)limit('request_timeout'))),
                'skip_crawl'      => parse_ext_list((string)($_POST['skip_crawl'] ?? SKIP_CRAWL_DEFAULT)),
                'skip_check'      => parse_ext_list((string)($_POST['skip_check'] ?? SKIP_CHECK_DEFAULT)),
                'check_external'  => !empty($_POST['check_external']),
                'check_resources' => !empty($_POST['check_resources']),
            ];
            $now = time();
            $pdo = db();
            $pdo->beginTransaction();
            $pdo->prepare('INSERT INTO scans(start_url, options, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?)')
                ->execute([$start, json_encode($opt, JSON_UNESCAPED_SLASHES), 'running', $now, $now]);
            $newId = (int)$pdo->lastInsertId();
            $pdo->prepare('INSERT INTO links(scan_id, url, crawl) VALUES(?, ?, 1)')->execute([$newId, $start]);
            $old = $pdo->prepare('SELECT id FROM scans ORDER BY id DESC LIMIT -1 OFFSET ?');
            $old->execute([(int)limit('keep_scans')]);
            foreach ($old->fetchAll(PDO::FETCH_COLUMN) as $oid) $pdo->prepare('DELETE FROM scans WHERE id = ?')->execute([$oid]);
            $pdo->commit();
            plog('INFO', "Scan #$newId started: $start (scope $scope)");
            json_out(['ok' => true, 'scan' => scan_public(get_scan($newId)), 'counts' => scan_counts($newId)]);
        }

        case 'run': {
            json_out(run_batch($sid));
        }

        case 'resume': {
            $s = get_scan($sid);
            if (!$s) fail('Scan not found.');
            if ($s['status'] === 'stopped') {
                db()->prepare("UPDATE scans SET status='running', updated_at=? WHERE id=?")->execute([time(), $sid]);
                $s = get_scan($sid);
            }
            json_out(['ok' => true, 'scan' => scan_public($s), 'counts' => scan_counts($sid)]);
        }

        case 'stop': {
            if (!get_scan($sid)) fail('Scan not found.');
            db()->prepare("UPDATE scans SET status='stopped', updated_at=? WHERE id=? AND status='running'")->execute([time(), $sid]);
            json_out(['ok' => true]);
        }

        case 'delete': {
            if (locked_scan() === $sid) fail('A batch of this scan is still running. Try again in a few seconds.');
            db()->prepare('DELETE FROM scans WHERE id = ?')->execute([$sid]);
            json_out(['ok' => true]);
        }

        case 'summary': {
            $s = get_scan($sid);
            if (!$s) fail('Scan not found.');
            $codes = db()->prepare("SELECT http_code, status, COUNT(*) c FROM links WHERE scan_id = ? AND status != 'pending'
                                    GROUP BY http_code, status ORDER BY c DESC LIMIT 14");
            $codes->execute([$sid]);
            $red = db()->prepare('SELECT COUNT(*) FROM links WHERE scan_id = ? AND redirect_count > 0');
            $red->execute([$sid]);
            json_out(['ok' => true, 'scan' => scan_public($s), 'counts' => scan_counts($sid),
                      'codes' => $codes->fetchAll(), 'redirected' => (int)$red->fetchColumn(),
                      'options' => ['check_external' => !empty($s['opt']['check_external']), 'check_resources' => !empty($s['opt']['check_resources']),
                                    'hosts' => $s['opt']['hosts'] ?? []]]);
        }

        case 'issues': {
            if (!get_scan($sid)) fail('Scan not found.');
            $per  = 50;
            $page = max(1, (int)($_POST['page'] ?? 1));
            [$w, $p] = issues_filter((string)($_POST['filter'] ?? 'attention'), trim((string)($_POST['q'] ?? '')));
            $cnt = db()->prepare("SELECT COUNT(*) FROM links WHERE $w");
            $cnt->execute(array_merge([$sid], $p));
            $total = (int)$cnt->fetchColumn();
            $st = db()->prepare("SELECT id, url, status, http_code, error, final_url, redirect_count, redirect_chain, response_ms
                                 FROM links WHERE $w
                                 ORDER BY CASE status WHEN 'broken' THEN 0 WHEN 'unverified' THEN 1 ELSE 2 END, id
                                 LIMIT $per OFFSET " . (($page - 1) * $per));
            $st->execute(array_merge([$sid], $p));
            json_out(['ok' => true, 'total' => $total, 'page' => $page, 'pages' => max(1, (int)ceil($total / $per)),
                      'rows' => attach_sources($st->fetchAll(), 3)]);
        }
    }
    fail('Unknown action.');
}

// ============================================================================
// ROUTER
// ============================================================================
$METHOD = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');

if ($METHOD === 'POST' && isset($_POST['pdlf_login'])) {
    handle_login();
}
if ($METHOD === 'POST' && isset($_POST['pdlf_logout'])) {
    if (csrf_ok()) {
        plog('INFO', 'Logout');
        reset_session();
    }
    header('Location: ' . self_url());
    exit;
}
if ($METHOD === 'GET' && ($_GET['export'] ?? '') === 'csv') {
    if (!is_authenticated()) { http_response_code(401); exit('Please sign in first.'); }
    session_write_close();
    export_csv();
}
if ($METHOD === 'POST' && isset($_POST['action'])) {
    handle_api((string)$_POST['action']);
}
if (!is_authenticated()) {
    login_page();
}

// ============================================================================
// DASHBOARD
// ============================================================================
$DATA_PUBLIC = data_dir_is_public(DATA_DIR);
$BOOT = [
    'csrf'       => $_SESSION['csrf_token'],
    'defaultUrl' => (is_https() ? 'https' : 'http') . '://' . preg_replace('/[^A-Za-z0-9.:\-\[\]]/', '', (string)($_SERVER['HTTP_HOST'] ?? '')),
    'probe'      => $DATA_PUBLIC ? data_probe_url(DATA_DIR) : null,
    'dataPublic' => $DATA_PUBLIC,
    'skipCrawl'  => SKIP_CRAWL_DEFAULT,
    'skipCheck'  => SKIP_CHECK_DEFAULT,
    'timeout'    => (int)limit('request_timeout'),
    'maxLinks'   => 500,
];

page_head('PDLF — Personal Dead Link Finder');
?>
<div class="wrap">
  <div class="top">
    <h1>🔗 PDLF <small>Personal Dead Link Finder · v<?= e(PDLF_VERSION) ?></small></h1>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">
      <button class="secondary" name="pdlf_logout" value="1" type="submit">Sign out</button>
    </form>
  </div>

  <div id="exposed" class="banner err" hidden>
    <b>Your private data folder is publicly downloadable.</b> Anyone who guesses the file names could fetch your database.
    Fix it now: on nginx add <code>location ~ /\.pdlf_data { deny all; }</code> to the site config, or move the folder out of the web root
    by setting the <code>PDLF_DATA_DIR</code> environment variable.
  </div>
  <div id="inside" class="banner warn" hidden>
    The data folder sits inside the web root. Apache/IIS are protected by the generated <code>.htaccess</code>/<code>web.config</code>;
    nginx ignores those, so make sure a deny rule exists (this page checks it automatically and will shout if the folder is reachable).
  </div>

  <!-- NEW SCAN -->
  <div class="card">
    <h2>New scan</h2>
    <div class="row">
      <div class="field wide"><label for="startUrl">Start URL (your site)</label>
        <input type="text" id="startUrl" autocomplete="off" spellcheck="false"></div>
      <div class="field sm"><label for="maxLinks">Max links</label>
        <input type="number" id="maxLinks" min="1" max="20000"></div>
      <div class="field sm"><label for="timeout">Request timeout</label>
        <select id="timeout"><option value="5">5 s</option><option value="10">10 s</option><option value="15">15 s</option><option value="20">20 s</option><option value="30">30 s</option></select></div>
    </div>

    <h3>Crawl scope</h3>
    <div class="scope">
      <label class="chk"><input type="radio" name="scope" value="single" checked> This host only</label>
      <label class="chk"><input type="radio" name="scope" value="selected"> Selected subdomains</label>
      <label class="chk"><input type="radio" name="scope" value="all"> All subdomains</label>
    </div>
    <div id="hostBox" hidden>
      <button type="button" class="secondary" id="discoverBtn">🔍 Discover subdomains linked from the start page</button>
      <div id="hostList"></div>
      <label for="extraHosts">Additional hosts to crawl (comma separated, e.g. <code>blog.example.com, shop.example.com</code>)</label>
      <input type="text" id="extraHosts" autocomplete="off" spellcheck="false">
    </div>
    <p class="muted small">Links to hosts outside the scope are never crawled. Enable “check external links” below to verify them too.</p>

    <div class="row">
      <!-- <label class="chk"><input type="checkbox" id="checkExternal"> Check external links (verified, never crawled)</label> -->
      <label class="chk"><input type="checkbox" id="checkResources"> Also check images, CSS, scripts &amp; embeds</label>
    </div>

    <details class="adv">
      <summary>File exclusions</summary>
      <div class="row">
        <div class="field"><label for="skipCrawl">Don’t crawl (still checked): extensions</label>
          <input type="text" id="skipCrawl" autocomplete="off" spellcheck="false"></div>
        <div class="field"><label for="skipCheck">Don’t check at all: extensions</label>
          <input type="text" id="skipCheck" autocomplete="off" spellcheck="false" placeholder="e.g. mp4,iso"></div>
      </div>
      <p class="muted small">“Don’t crawl” suits files that cannot contain links (PDF, images…): they are verified with a light request but never parsed. “Don’t check” removes matching URLs from the scan entirely.</p>
    </details>

    <p><button type="button" id="startBtn">▶ Start scan</button></p>
  </div>

  <!-- PROGRESS -->
  <div class="card" id="progressCard" hidden>
    <h2 id="progressTitle">Scan</h2>
    <progress id="prog" max="100" value="0"></progress>
    <div class="muted small" id="progText"></div>
    <div class="counts">
      <div class="tile t-working"><span>Working</span><b id="cWorking">0</b></div>
      <div class="tile t-broken"><span>Broken</span><b id="cBroken">0</b></div>
      <div class="tile t-unverified"><span>Unverified</span><b id="cUnverified">0</b></div>
      <div class="tile t-pending"><span>Pending</span><b id="cPending">0</b></div>
      <div class="tile t-total"><span>Discovered</span><b id="cTotal">0</b></div>
    </div>
    <div class="row">
      <button type="button" class="secondary" id="pauseBtn" hidden>⏸ Pause</button>
      <button type="button" id="resumeBtn" hidden>⏵ Resume</button>
      <button type="button" class="danger" id="stopBtn" hidden>■ Stop</button>
      <span class="muted small" id="current"></span>
    </div>
    <div id="log" role="log" aria-live="polite">Ready.</div>
  </div>

  <!-- HISTORY -->
  <div class="card">
    <h2>Scan history</h2>
    <table class="grid" id="history"><thead><tr>
      <th>#</th><th>Started</th><th>Start URL</th><th>Status</th><th>Checked</th><th>Working</th><th>Broken</th><th>Unverified</th><th></th>
    </tr></thead><tbody></tbody></table>
  </div>

  <!-- REPORT -->
  <div class="card" id="reportCard" hidden>
    <h2 id="reportTitle">Report</h2>
    <div class="banner warn" id="truncNote" hidden>The “Max links” limit was reached, so some links were never discovered. Raise it and scan again for full coverage.</div>
    <div class="counts" id="tiles"></div>
    <div class="report-grid">
      <div id="donut"></div>
      <div class="cbars" id="codeBars"></div>
    </div>
    <div class="toolbar">
      <label for="filter" class="muted nomargin">Show</label>
      <select id="filter">
        <option value="attention">Broken + Unverified</option>
        <option value="broken">Broken only</option>
        <option value="unverified">Unverified only</option>
        <option value="redirected">Redirected</option>
        <option value="working">Working</option>
        <option value="all">All checked links</option>
      </select>
      <input type="text" id="search" placeholder="Filter by URL…" autocomplete="off">
      <a class="btn secondary" id="csvLink" href="#">⬇ Export CSV</a>
    </div>
    <table class="grid" id="issues"><thead><tr>
      <th class="w-status">Status</th><th>URL</th><th>Details</th><th>Found on</th>
    </tr></thead><tbody></tbody></table>
    <div class="pager">
      <span class="muted small" id="pageInfo"></span>
      <span><button type="button" class="secondary" id="prevBtn">← Prev</button> <button type="button" class="secondary" id="nextBtn">Next →</button></span>
    </div>
  </div>
</div>

<script type="application/json" id="boot"><?= json_encode($BOOT, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES) ?></script>
<script nonce="<?= e($NONCE) ?>">
(() => {
'use strict';
const BOOT = JSON.parse(document.getElementById('boot').textContent);
const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const NS = 'http://www.w3.org/2000/svg';

// Safe DOM builder: everything that comes from crawled pages is inserted as text, never as HTML.
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === false || v == null) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null) n.append(kid);
  return n;
}
const fmtTime = ts => ts ? new Date(ts * 1000).toLocaleString() : '—';
const shorten = (s, n = 70) => s.length > n ? s.slice(0, n - 1) + '…' : s;
const pct = (a, b) => b ? Math.round(a / b * 100) : 0;

async function api(action, data = {}) {
  const fd = new FormData();
  fd.append('action', action);
  fd.append('csrf_token', BOOT.csrf);
  for (const [k, v] of Object.entries(data)) fd.append(k, v);
  const r = await fetch(location.pathname, { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'X-CSRF-Token': BOOT.csrf } });
  if (r.status === 401) { location.reload(); throw new Error('Session expired'); }
  let j;
  try { j = await r.json(); } catch { throw new Error('Unexpected server response (HTTP ' + r.status + ')'); }
  return j;
}

// ---------------------------------------------------------------- state
let activeId = null, running = false, pauseReq = false;
let rep = { id: null, filter: 'attention', page: 1, pages: 1 };

// ---------------------------------------------------------------- defaults & warnings
$('startUrl').value = BOOT.defaultUrl;
$('maxLinks').value = BOOT.maxLinks;
$('timeout').value = String(BOOT.timeout);
if (![...$('timeout').options].some(o => o.value === $('timeout').value)) $('timeout').append(el('option', { value: $('timeout').value, text: $('timeout').value + ' s' }));
$('timeout').value = String(BOOT.timeout);
$('skipCrawl').value = BOOT.skipCrawl;
$('skipCheck').value = BOOT.skipCheck;
if (BOOT.dataPublic) {
  $('inside').hidden = false;
  if (BOOT.probe) {
    fetch(BOOT.probe, { cache: 'no-store', credentials: 'omit' })
      .then(r => r.ok ? r.text() : '').then(t => { if (t.includes('PDLF-PROBE')) { $('exposed').hidden = false; $('inside').hidden = true; } })
      .catch(() => {});
  }
}

function log(msg) {
  const box = $('log');
  box.textContent += '\n' + msg;
  const lines = box.textContent.split('\n');
  if (lines.length > 300) box.textContent = lines.slice(-300).join('\n');
  box.scrollTop = box.scrollHeight;
}

// ---------------------------------------------------------------- scope UI
const scopeVal = () => document.querySelector('input[name=scope]:checked').value;
document.querySelectorAll('input[name=scope]').forEach(r => r.addEventListener('change', () => { $('hostBox').hidden = scopeVal() !== 'selected'; }));

$('discoverBtn').addEventListener('click', async () => {
  const b = $('discoverBtn'); b.disabled = true; b.textContent = 'Discovering…';
  try {
    const r = await api('discover', { start_url: $('startUrl').value });
    if (!r.ok) { alert(r.error); return; }
    const box = $('hostList'); box.replaceChildren();
    if (!r.hosts.length) box.append(el('span', { class: 'muted small', text: 'No other subdomains are linked from the start page. Add them manually below.' }));
    for (const h of r.hosts) box.append(el('label', { class: 'chk' }, el('input', { type: 'checkbox', value: h }), h));
  } catch (e) { alert(e.message); }
  finally { b.disabled = false; b.textContent = '🔍 Discover subdomains linked from the start page'; }
});

// ---------------------------------------------------------------- scan control
function showProgress(scan, counts) {
  $('progressCard').hidden = false;
  $('progressTitle').textContent = `Scan #${scan.id} — ${shorten(scan.start_url, 80)}`;
  setCounts(counts);
}
function setCounts(c) {
  $('cWorking').textContent = c.working; $('cBroken').textContent = c.broken; $('cUnverified').textContent = c.unverified;
  $('cPending').textContent = c.pending; $('cTotal').textContent = c.total;
  $('prog').value = pct(c.checked, c.total);
  $('progText').textContent = `${c.checked} of ${c.total} discovered links checked (${pct(c.checked, c.total)}%) — the total grows while pages are crawled`;
}
function buttons() {
  $('pauseBtn').hidden = !running;
  $('stopBtn').hidden = !(running || activeId);
  $('resumeBtn').hidden = running || !activeId;
  $('startBtn').disabled = running;
}

$('startBtn').addEventListener('click', async () => {
  const hosts = [...document.querySelectorAll('#hostList input:checked')].map(i => i.value);
  const extra = $('extraHosts').value.trim(); if (extra) hosts.push(extra);
  const b = $('startBtn'); b.disabled = true;
  try {
    const r = await api('start', {
      start_url: $('startUrl').value, max_links: $('maxLinks').value, timeout: $('timeout').value,
      scope: scopeVal(), hosts: hosts.join(','), skip_crawl: $('skipCrawl').value, skip_check: $('skipCheck').value,
      /*check_external: $('checkExternal').checked ? '1' : '',*/ check_resources: $('checkResources').checked ? '1' : '',
    });
    if (!r.ok) { alert(r.error); return; }
    $('reportCard').hidden = true;
    $('log').textContent = 'Scan #' + r.scan.id + ' created at ' + new Date().toLocaleTimeString();
    showProgress(r.scan, r.counts);
    refreshHistory();
    runLoop(r.scan.id);
  } catch (e) { alert(e.message); }
  finally { b.disabled = running; }
});

$('pauseBtn').addEventListener('click', () => { pauseReq = true; $('pauseBtn').disabled = true; log('Pausing after the current batch…'); });
$('resumeBtn').addEventListener('click', async () => { if (activeId) { await api('resume', { scan_id: activeId }); runLoop(activeId); } });
$('stopBtn').addEventListener('click', async () => {
  if (!activeId || !confirm('Stop this scan? Results so far are kept and you can resume it later from the history.')) return;
  pauseReq = true;
  await api('stop', { scan_id: activeId });
  log('■ Scan stopped. It can be resumed from the history.');
  if (!running) { activeId = null; buttons(); }
  refreshHistory();
});

async function runLoop(id) {
  if (running) return;
  running = true; pauseReq = false; activeId = id;
  $('pauseBtn').disabled = false; buttons();
  let busy = 0, idle = 0;
  try {
    while (!pauseReq) {
      const r = await api('run', { scan_id: id });
      if (!r.ok) { log('✖ ' + r.error); break; }
      if (r.busy) {
        if (++busy > 20) { log('✖ Another batch keeps running. Try again in a minute.'); break; }
        log('Another batch is still running — waiting…'); await sleep(3000); continue;
      }
      busy = 0;
      setCounts(r.counts);
      $('current').textContent = r.last ? 'Last: ' + shorten(r.last, 80) : '';
      for (const n of r.notes || []) log(n);
      log(`Batch: ${r.processed} checked, ${r.discovered} new links discovered · ${r.counts.pending} pending`);
      if (r.done) {
        log('✔ Scan complete.' + (r.truncated ? ' (Max links limit reached.)' : ''));
        activeId = null;
        await openReport(id);
        break;
      }
      idle = (r.processed === 0 && r.discovered === 0) ? idle + 1 : 0;
      if (idle >= 5) { log('✖ No progress for several batches — stopping the loop.'); break; }
      await sleep(100);
    }
    if (pauseReq && activeId) log('⏸ Paused. Press Resume to continue.');
  } catch (e) { log('✖ ' + e.message); }
  finally { running = false; buttons(); refreshHistory(); }
}

// ---------------------------------------------------------------- history
async function refreshHistory() {
  let r;
  try { r = await api('state'); } catch { return; }
  if (!r.ok) return;
  const tb = $('history').querySelector('tbody'); tb.replaceChildren();
  if (!r.scans.length) tb.append(el('tr', {}, el('td', { colspan: 9, class: 'muted', text: 'No scans yet.' })));
  for (const s of r.scans) {
    const c = s.counts;
    const open = s.status !== 'completed';
    const live = s.active || (running && activeId === s.id);
    const label = s.status === 'completed' ? 'Completed' : live ? 'Running' : s.status === 'stopped' ? 'Stopped' : 'Interrupted';
    const cls = s.status === 'completed' ? 'b-working' : live ? 'b-running' : 'b-unverified';
    tb.append(el('tr', {},
      el('td', { text: s.id }),
      el('td', { text: fmtTime(s.created_at) }),
      el('td', { class: 'url', text: shorten(s.start_url, 60) }),
      el('td', {}, el('span', { class: 'badge ' + cls, text: label })),
      el('td', { text: `${c.checked}/${c.total}` }),
      el('td', { text: c.working }), el('td', { text: c.broken }), el('td', { text: c.unverified }),
      el('td', {},
        el('button', { class: 'linklike', type: 'button', text: 'Report', onclick: () => openReport(s.id) }),
        open && !live ? el('button', { class: 'linklike', type: 'button', text: 'Resume', onclick: async () => {
          const x = await api('resume', { scan_id: s.id }); if (!x.ok) return alert(x.error);
          $('log').textContent = 'Resuming scan #' + s.id; showProgress(x.scan, x.counts); runLoop(s.id);
        } }) : null,
        el('a', { class: 'linklike', href: `?export=csv&scan=${s.id}&filter=all`, text: 'CSV' }),
        !live ? el('button', { class: 'linklike', type: 'button', text: 'Delete', onclick: async () => {
          if (!confirm(`Delete scan #${s.id} and all its results?`)) return;
          const x = await api('delete', { scan_id: s.id }); if (!x.ok) return alert(x.error);
          if (rep.id === s.id) $('reportCard').hidden = true;
          refreshHistory();
        } }) : null)));
  }
  // On page load: surface the newest unfinished scan so it can be resumed in one click.
  const unfinished = r.scans.find(s => s.status !== 'completed' && s.counts.pending > 0);
  if (unfinished && !running && !activeId && $('progressCard').hidden) {
    activeId = unfinished.id; showProgress(unfinished, unfinished.counts); buttons();
    $('log').textContent = `Scan #${unfinished.id} is unfinished (${unfinished.counts.pending} links pending). Press Resume to continue.`;
  }
}

// ---------------------------------------------------------------- report
function donut(parts) {
  const total = parts.reduce((a, p) => a + p.value, 0);
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 120 120'); svg.setAttribute('width', '170'); svg.setAttribute('height', '170');
  svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Link classification');
  const R = 46, C = 2 * Math.PI * R;
  const mk = (cls, extra = {}) => {
    const c = document.createElementNS(NS, 'circle');
    for (const [k, v] of Object.entries({ cx: 60, cy: 60, r: R, 'stroke-width': 18, class: cls, ...extra })) c.setAttribute(k, v);
    return c;
  };
  svg.append(mk('seg-bg'));
  let off = 0;
  for (const p of parts) {
    if (!p.value) continue;
    const len = p.value / total * C;
    const c = mk('seg seg-' + p.key, { 'stroke-dasharray': `${len} ${C - len}`, 'stroke-dashoffset': -off, transform: 'rotate(-90 60 60)' });
    const t = document.createElementNS(NS, 'title'); t.textContent = `${p.label}: ${p.value}`; c.append(t);
    svg.append(c); off += len;
  }
  const tx = document.createElementNS(NS, 'text');
  tx.setAttribute('x', 60); tx.setAttribute('y', 65); tx.setAttribute('text-anchor', 'middle'); tx.textContent = total;
  svg.append(tx);
  return svg;
}

async function openReport(id) {
  const r = await api('summary', { scan_id: id });
  if (!r.ok) return alert(r.error);
  rep.id = id; rep.page = 1;
  const c = r.counts;
  $('reportCard').hidden = false;
  $('reportTitle').textContent = `Report — scan #${id} · ${shorten(r.scan.start_url, 70)}`;
  $('truncNote').hidden = !r.scan.truncated;

  rep.summary = { c, redirected: r.redirected };
  openReportTilesOnly();

  $('donut').replaceChildren(donut([
    { key: 'working', label: 'Working', value: c.working }, { key: 'broken', label: 'Broken', value: c.broken },
    { key: 'unverified', label: 'Unverified', value: c.unverified }]));
  const bars = $('codeBars'); bars.replaceChildren(el('div', { class: 'muted small', text: 'Responses by HTTP status code' }));
  const max = Math.max(1, ...r.codes.map(x => x.c));
  for (const x of r.codes) {
    const f = el('i', { class: 'fill b-' + x.status });
    f.style.width = Math.max(1, x.c / max * 100) + '%';
    bars.append(el('div', { class: 'cbar' }, el('span', { class: 'code', text: x.http_code || 'ERR' }), el('span', { class: 'track' }, f), el('span', { text: x.c })));
  }
  await loadIssues();
  $('reportCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openReportTilesOnly() {
  const { c, redirected } = rep.summary;
  const tile = (key, label, n, filter) => el('button', { type: 'button', class: `tile t-${key}` + (rep.filter === filter ? ' on' : ''),
    onclick: () => { $('filter').value = filter; rep.filter = filter; rep.page = 1; openReportTilesOnly(); loadIssues(); } },
    el('span', { text: label }), el('b', { text: n }));
  $('tiles').replaceChildren(tile('working', 'Working', c.working, 'working'), tile('broken', 'Broken', c.broken, 'broken'),
    tile('unverified', 'Unverified', c.unverified, 'unverified'), tile('redirected', 'Redirected', redirected, 'redirected'));
}

async function loadIssues() {
  if (rep.id == null) return;
  const q = $('search').value.trim();
  const r = await api('issues', { scan_id: rep.id, filter: rep.filter, page: rep.page, q });
  if (!r.ok) return alert(r.error);
  rep.pages = r.pages; rep.page = r.page;
  $('csvLink').href = `?export=csv&scan=${rep.id}&filter=${encodeURIComponent(rep.filter === 'attention' ? 'attention' : rep.filter)}`;
  const tb = $('issues').querySelector('tbody'); tb.replaceChildren();
  if (!r.rows.length) tb.append(el('tr', {}, el('td', { colspan: 4, class: 'muted', text: rep.filter === 'attention' && !q ? 'No broken or unverified links. 🎉' : 'Nothing matches this filter.' })));
  for (const x of r.rows) {
    const code = x.http_code ? String(x.http_code) : 'ERR';
    const details = el('div', {});
    if (x.error) details.append(el('div', { text: x.error }));
    if (x.chain.length) {
      const final = x.final_url || x.url;
      details.append(el('details', {},
        el('summary', { class: 'small', text: `↪ ${x.chain.length} redirect${x.chain.length > 1 ? 's' : ''} → ${shorten(final, 60)}` }),
        el('ol', { class: 'chain' },
          ...x.chain.map(h => el('li', { text: `${h.code} ${h.code === 301 || h.code === 308 ? '(permanent)' : '(temporary)'} → ${h.to}` })),
          el('li', { text: `Final: ${x.http_code || 'ERR'}  ${final}` }))));
    }
    if (!x.error && !x.chain.length) details.append(el('span', { class: 'muted', text: '—' }));
    const src = el('div', { class: 'src' });
    for (const s of x.sources) src.append(el('div', {}, el('a', { href: s, target: '_blank', rel: 'noopener noreferrer nofollow', text: shorten(s, 60) })));
    if (x.source_count > x.sources.length) src.append(el('div', { text: `+ ${x.source_count - x.sources.length} more page(s)` }));
    if (!x.sources.length) src.append('start page / redirect');
    tb.append(el('tr', {},
      el('td', {}, el('span', { class: 'badge b-' + x.status, text: code })),
      el('td', { class: 'url' }, el('a', { href: x.url, target: '_blank', rel: 'noopener noreferrer nofollow', text: x.url })),
      el('td', {}, details), el('td', {}, src)));
  }
  $('pageInfo').textContent = `${r.total} link${r.total === 1 ? '' : 's'} · page ${r.page} of ${r.pages}`;
  $('prevBtn').disabled = r.page <= 1; $('nextBtn').disabled = r.page >= r.pages;
}

$('filter').addEventListener('change', () => { rep.filter = $('filter').value; rep.page = 1; if (rep.summary) openReportTilesOnly(); loadIssues(); });
let st; $('search').addEventListener('input', () => { clearTimeout(st); st = setTimeout(() => { rep.page = 1; loadIssues(); }, 300); });
$('prevBtn').addEventListener('click', () => { if (rep.page > 1) { rep.page--; loadIssues(); } });
$('nextBtn').addEventListener('click', () => { if (rep.page < rep.pages) { rep.page++; loadIssues(); } });

buttons();
refreshHistory();
})();
</script>
<?php page_foot();
