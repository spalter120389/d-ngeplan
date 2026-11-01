<?php
/*
 * Growbuch - PHP-Backend fuer Webhosting (PHP 7.4+, PDO SQLite).
 * Aufruf: api.php?r=<route>[&m=PUT|DELETE]
 * Beim ersten Aufruf wird config.local.php mit einem zufaelligen Datenordner angelegt.
 */
declare(strict_types=1);

const SESSION_DAYS = 30;
const MAX_PHOTO = 20 * 1024 * 1024;
const PHOTO_TYPES = ['image/jpeg' => '.jpg', 'image/png' => '.png', 'image/webp' => '.webp', 'image/gif' => '.gif'];

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store');

// ---------- Konfiguration & Datenordner ----------

$cfg = __DIR__ . '/config.local.php';
if (!is_file($cfg)) {
    $dir = 'data-' . bin2hex(random_bytes(16));
    $php = "<?php\n// Automatisch erzeugt. Name des Datenordners geheim halten.\ndefine('DATA_DIR', __DIR__ . '/" . $dir . "');\n";
    if (@file_put_contents($cfg, $php, LOCK_EX) === false) {
        fail(500, 'Kann config.local.php nicht anlegen. Gib dem Ordner Schreibrechte (z. B. 755) und lade die Seite neu.');
    }
}
require $cfg;

if (!is_dir(DATA_DIR . '/photos') && !@mkdir(DATA_DIR . '/photos', 0750, true)) {
    fail(500, 'Kann den Datenordner nicht anlegen. Gib dem Ordner Schreibrechte und lade die Seite neu.');
}
foreach (['/.htaccess' => "Require all denied\nDeny from all\n", '/index.html' => '', '/photos/index.html' => ''] as $f => $c) {
    if (!is_file(DATA_DIR . $f)) @file_put_contents(DATA_DIR . $f, $c);
}

function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO('sqlite:' . DATA_DIR . '/growbuch.sqlite', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE,
            pw TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS grows(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            data TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS entries(id TEXT PRIMARY KEY, grow_id TEXT NOT NULL REFERENCES grows(id) ON DELETE CASCADE,
            data TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS photos(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            file TEXT NOT NULL, mime TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS failures(ip TEXT PRIMARY KEY, count INTEGER NOT NULL, since REAL NOT NULL);
    ");
    return $pdo;
}

// ---------- Helfer ----------

function out(int $code, $obj): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($obj, JSON_UNESCAPED_UNICODE);
    exit;
}
function fail(int $code, string $msg): void { out($code, ['error' => $msg]); }

function body(): array {
    if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) fail(400, 'JSON erwartet.');
    $b = json_decode(file_get_contents('php://input') ?: '{}', true);
    if (!is_array($b)) fail(400, 'Ungültiges JSON.');
    return $b;
}

function is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
}

function set_session_cookie(string $token, int $maxAge): void {
    setcookie('gb_session', $token, [
        'expires' => $maxAge ? time() + $maxAge : time() - 3600,
        'path' => cookie_path(), 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Strict',
    ]);
}
function cookie_path(): string {
    $p = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    return $p === '' ? '/' : $p . '/';
}

function current_user(): ?array {
    $t = $_COOKIE['gb_session'] ?? '';
    if ($t === '') return null;
    $st = db()->prepare('SELECT u.id, u.name, u.admin FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?');
    $st->execute([hash('sha256', $t), microtime(true)]);
    return $st->fetch() ?: null;
}

function start_session(int $uid): void {
    $t = bin2hex(random_bytes(32));
    db()->prepare('DELETE FROM sessions WHERE expires < ?')->execute([microtime(true)]);
    db()->prepare('INSERT INTO sessions VALUES(?,?,?)')->execute([hash('sha256', $t), $uid, microtime(true) + SESSION_DAYS * 86400]);
    set_session_cookie($t, SESSION_DAYS * 86400);
}

function user_count(): int { return (int)db()->query('SELECT COUNT(*) FROM users')->fetchColumn(); }
function valid_name($n): bool { return is_string($n) && preg_match('/^[\w.\-]{2,32}$/u', $n) === 1; }
function valid_date($d): bool { return is_string($d) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) === 1; }
function new_id(string $p): string { return $p . '-' . bin2hex(random_bytes(6)); }

function client_ip(): string { return $_SERVER['REMOTE_ADDR'] ?? '?'; }
function too_many_failures(): bool {
    $st = db()->prepare('SELECT count, since FROM failures WHERE ip = ?');
    $st->execute([client_ip()]);
    $r = $st->fetch();
    if (!$r) return false;
    if (microtime(true) - $r['since'] > 900) {
        db()->prepare('DELETE FROM failures WHERE ip = ?')->execute([client_ip()]);
        return false;
    }
    return $r['count'] >= 10;
}
function note_failure(): void {
    db()->prepare('INSERT OR IGNORE INTO failures VALUES(?,0,?)')->execute([client_ip(), microtime(true)]);
    db()->prepare('UPDATE failures SET count = count + 1 WHERE ip = ?')->execute([client_ip()]);
    usleep(800000);
}

function own_grow(array $u, string $gid): ?array {
    $st = db()->prepare('SELECT * FROM grows WHERE id = ? AND user_id = ?');
    $st->execute([$gid, $u['id']]);
    return $st->fetch() ?: null;
}

function delete_photos(array $u, array $ids): void {
    foreach (array_unique($ids) as $pid) {
        if (!is_string($pid)) continue;
        $st = db()->prepare('SELECT file FROM photos WHERE id = ? AND user_id = ?');
        $st->execute([$pid, $u['id']]);
        $f = $st->fetchColumn();
        if ($f === false) continue;
        db()->prepare('DELETE FROM photos WHERE id = ?')->execute([$pid]);
        @unlink(DATA_DIR . '/photos/' . $f);
    }
}
function photos_of(string $json): array {
    $d = json_decode($json, true);
    return is_array($d['photos'] ?? null) ? $d['photos'] : [];
}

// ---------- Routing ----------

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'POST' && in_array($_GET['m'] ?? '', ['PUT', 'DELETE'], true)) $method = $_GET['m'];
$parts = array_values(array_filter(explode('/', (string)($_GET['r'] ?? '')), 'strlen'));
$route = implode('/', $parts);

// Schreibende Anfragen nur von der eigenen Seite
if ($method !== 'GET' && !empty($_SERVER['HTTP_ORIGIN'])) {
    $host = parse_url($_SERVER['HTTP_ORIGIN'], PHP_URL_HOST) . (parse_url($_SERVER['HTTP_ORIGIN'], PHP_URL_PORT) ? ':' . parse_url($_SERVER['HTTP_ORIGIN'], PHP_URL_PORT) : '');
    if ($host !== ($_SERVER['HTTP_HOST'] ?? '')) fail(403, 'Fremde Herkunft.');
}

try {
    // --- ohne Anmeldung ---
    if ($route === 'me' && $method === 'GET') {
        $u = current_user();
        out(200, ['user' => $u['name'] ?? null, 'isAdmin' => (bool)($u['admin'] ?? false), 'canRegister' => user_count() === 0]);
    }
    if ($route === 'login' && $method === 'POST') {
        if (too_many_failures()) fail(429, 'Zu viele Fehlversuche. Warte 15 Minuten.');
        $b = body();
        $st = db()->prepare('SELECT id, name, pw FROM users WHERE name = ?');
        $st->execute([(string)($b['username'] ?? '')]);
        $r = $st->fetch();
        if (!$r || !password_verify((string)($b['password'] ?? ''), $r['pw'])) {
            note_failure();
            fail(401, 'Benutzername oder Passwort falsch.');
        }
        start_session((int)$r['id']);
        out(200, ['user' => $r['name']]);
    }
    if ($route === 'register' && $method === 'POST') {
        if (user_count() > 0) fail(403, 'Registrierung ist geschlossen. Neue Benutzer legt der Admin unter „Konto“ an.');
        $b = body();
        if (!valid_name($b['username'] ?? null)) fail(400, 'Benutzername: 2–32 Zeichen, nur Buchstaben, Ziffern, . _ -');
        if (strlen((string)($b['password'] ?? '')) < 8) fail(400, 'Passwort muss mindestens 8 Zeichen haben.');
        db()->prepare('INSERT INTO users(name,pw,admin,created) VALUES(?,?,1,?)')
            ->execute([$b['username'], password_hash((string)$b['password'], PASSWORD_DEFAULT), microtime(true)]);
        start_session((int)db()->lastInsertId());
        out(200, ['user' => $b['username']]);
    }
    if ($route === 'logout' && $method === 'POST') {
        if (!empty($_COOKIE['gb_session'])) db()->prepare('DELETE FROM sessions WHERE token = ?')->execute([hash('sha256', $_COOKIE['gb_session'])]);
        set_session_cookie('', 0);
        out(200, ['ok' => true]);
    }

    // --- ab hier angemeldet ---
    $u = current_user();
    if (!$u) fail(401, 'Bitte anmelden.');

    if ($route === 'password' && $method === 'POST') {
        $b = body();
        $st = db()->prepare('SELECT pw FROM users WHERE id = ?');
        $st->execute([$u['id']]);
        if (!password_verify((string)($b['old'] ?? ''), (string)$st->fetchColumn())) fail(400, 'Aktuelles Passwort stimmt nicht.');
        if (strlen((string)($b['new'] ?? '')) < 8) fail(400, 'Neues Passwort muss mindestens 8 Zeichen haben.');
        db()->prepare('UPDATE users SET pw = ? WHERE id = ?')->execute([password_hash((string)$b['new'], PASSWORD_DEFAULT), $u['id']]);
        db()->prepare('DELETE FROM sessions WHERE user_id = ? AND token <> ?')->execute([$u['id'], hash('sha256', $_COOKIE['gb_session'])]);
        out(200, ['ok' => true]);
    }
    if ($route === 'users' && $method === 'POST') {
        if (!$u['admin']) fail(403, 'Nur der Admin kann Benutzer anlegen.');
        $b = body();
        if (!valid_name($b['username'] ?? null)) fail(400, 'Benutzername: 2–32 Zeichen, nur Buchstaben, Ziffern, . _ -');
        if (strlen((string)($b['password'] ?? '')) < 8) fail(400, 'Passwort muss mindestens 8 Zeichen haben.');
        try {
            db()->prepare('INSERT INTO users(name,pw,admin,created) VALUES(?,?,0,?)')
                ->execute([$b['username'], password_hash((string)$b['password'], PASSWORD_DEFAULT), microtime(true)]);
        } catch (PDOException $e) {
            fail(400, 'Diesen Benutzernamen gibt es schon.');
        }
        out(200, ['ok' => true]);
    }

    // Fotos
    if ($route === 'photos' && $method === 'POST') {
        $mime = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
        if (!isset(PHOTO_TYPES[$mime])) fail(400, 'Nur JPEG, PNG, WebP oder GIF.');
        $raw = file_get_contents('php://input');
        if ($raw === '' || $raw === false) fail(400, 'Leere Datei. Evtl. ist sie größer als das Upload-Limit deines Hostings.');
        if (strlen($raw) > MAX_PHOTO) fail(400, 'Foto ist zu groß (max. 20 MB).');
        if (function_exists('getimagesizefromstring') && @getimagesizefromstring($raw) === false) fail(400, 'Datei ist kein gültiges Bild.');
        $pid = bin2hex(random_bytes(16));
        $file = $pid . PHOTO_TYPES[$mime];
        if (file_put_contents(DATA_DIR . '/photos/' . $file, $raw) === false) fail(500, 'Foto konnte nicht gespeichert werden.');
        db()->prepare('INSERT INTO photos VALUES(?,?,?,?,?)')->execute([$pid, $u['id'], $file, $mime, microtime(true)]);
        out(200, ['id' => $pid]);
    }
    if (count($parts) === 2 && $parts[0] === 'photos' && $method === 'GET') {
        $st = db()->prepare('SELECT file, mime FROM photos WHERE id = ? AND user_id = ?');
        $st->execute([$parts[1], $u['id']]);
        $p = $st->fetch();
        if (!$p || !is_file(DATA_DIR . '/photos/' . $p['file'])) fail(404, 'Foto nicht gefunden.');
        header_remove('Cache-Control');
        header('Cache-Control: private, max-age=31536000, immutable');
        header('Content-Type: ' . $p['mime']);
        header('Content-Length: ' . filesize(DATA_DIR . '/photos/' . $p['file']));
        readfile(DATA_DIR . '/photos/' . $p['file']);
        exit;
    }

    // Grows
    if ($route === 'grows' && $method === 'GET') {
        $st = db()->prepare('SELECT id, data FROM grows WHERE user_id = ?');
        $st->execute([$u['id']]);
        out(200, array_map(function ($r) { return array_merge(json_decode($r['data'], true), ['id' => $r['id']]); }, $st->fetchAll()));
    }
    if (($route === 'grows' && $method === 'POST') || (count($parts) === 2 && $parts[0] === 'grows' && $method === 'PUT')) {
        $b = body();
        unset($b['id']);
        if (trim((string)($b['name'] ?? '')) === '' || !valid_date($b['startDate'] ?? null)) fail(400, 'Name und Startdatum fehlen.');
        $json = json_encode($b, JSON_UNESCAPED_UNICODE);
        if ($method === 'PUT') {
            $gid = $parts[1];
            if (!own_grow($u, $gid)) fail(404, 'Grow nicht gefunden.');
            db()->prepare('UPDATE grows SET data = ? WHERE id = ?')->execute([$json, $gid]);
        } else {
            $gid = new_id('g');
            db()->prepare('INSERT INTO grows VALUES(?,?,?,?)')->execute([$gid, $u['id'], $json, microtime(true)]);
        }
        out(200, array_merge($b, ['id' => $gid]));
    }
    if (count($parts) === 2 && $parts[0] === 'grows' && $method === 'DELETE') {
        if (!own_grow($u, $parts[1])) fail(404, 'Grow nicht gefunden.');
        db()->beginTransaction();
        $st = db()->prepare('SELECT data FROM entries WHERE grow_id = ?');
        $st->execute([$parts[1]]);
        $ids = [];
        foreach ($st->fetchAll() as $r) $ids = array_merge($ids, photos_of($r['data']));
        delete_photos($u, $ids);
        db()->prepare('DELETE FROM grows WHERE id = ?')->execute([$parts[1]]);
        db()->commit();
        out(200, ['ok' => true]);
    }
    if (count($parts) === 3 && $parts[0] === 'grows' && $parts[2] === 'export' && $method === 'GET') {
        $g = own_grow($u, $parts[1]);
        if (!$g) fail(404, 'Grow nicht gefunden.');
        $st = db()->prepare('SELECT id, data FROM entries WHERE grow_id = ? ORDER BY created');
        $st->execute([$parts[1]]);
        $grow = array_merge(json_decode($g['data'], true), ['id' => $g['id']]);
        $entries = array_map(function ($r) { return array_merge(json_decode($r['data'], true), ['id' => $r['id']]); }, $st->fetchAll());
        $name = preg_replace('/[^\w\-]+/u', '_', (string)($grow['name'] ?? 'grow'));
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="growbuch-' . $name . '-' . date('Y-m-d') . '.json"');
        echo json_encode(['grow' => $grow, 'entries' => $entries], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    // Eintraege
    if (count($parts) >= 3 && $parts[0] === 'grows' && $parts[2] === 'entries') {
        $gid = $parts[1];
        $eid = $parts[3] ?? null;
        if (!own_grow($u, $gid)) fail(404, 'Grow nicht gefunden.');
        if (!$eid && $method === 'GET') {
            $st = db()->prepare('SELECT id, data, created FROM entries WHERE grow_id = ?');
            $st->execute([$gid]);
            out(200, array_map(function ($r) {
                return array_merge(json_decode($r['data'], true), ['id' => $r['id'], 'createdAt' => (float)$r['created']]);
            }, $st->fetchAll()));
        }
        if ((!$eid && $method === 'POST') || ($eid && $method === 'PUT')) {
            $b = body();
            unset($b['id'], $b['createdAt']);
            if (!valid_date($b['date'] ?? null)) fail(400, 'Datum fehlt.');
            // nur eigene Fotos referenzieren
            $st = db()->prepare('SELECT id FROM photos WHERE user_id = ?');
            $st->execute([$u['id']]);
            $mine = array_flip($st->fetchAll(PDO::FETCH_COLUMN));
            $b['photos'] = array_values(array_filter(is_array($b['photos'] ?? null) ? $b['photos'] : [], function ($p) use ($mine) {
                return is_string($p) && isset($mine[$p]);
            }));
            $json = json_encode($b, JSON_UNESCAPED_UNICODE);
            if ($eid) {
                $st = db()->prepare('SELECT data FROM entries WHERE id = ? AND grow_id = ?');
                $st->execute([$eid, $gid]);
                $old = $st->fetchColumn();
                if ($old === false) fail(404, 'Eintrag nicht gefunden.');
                delete_photos($u, array_diff(photos_of($old), $b['photos']));
                db()->prepare('UPDATE entries SET data = ? WHERE id = ?')->execute([$json, $eid]);
            } else {
                $eid = new_id('e');
                db()->prepare('INSERT INTO entries VALUES(?,?,?,?)')->execute([$eid, $gid, $json, microtime(true)]);
            }
            out(200, array_merge($b, ['id' => $eid]));
        }
        if ($eid && $method === 'DELETE') {
            $st = db()->prepare('SELECT data FROM entries WHERE id = ? AND grow_id = ?');
            $st->execute([$eid, $gid]);
            $old = $st->fetchColumn();
            if ($old !== false) {
                delete_photos($u, photos_of($old));
                db()->prepare('DELETE FROM entries WHERE id = ?')->execute([$eid]);
            }
            out(200, ['ok' => true]);
        }
    }
    fail(404, 'Nicht gefunden.');
} catch (Throwable $e) {
    error_log('Growbuch: ' . $e->getMessage());
    fail(500, 'Interner Fehler.');
}
