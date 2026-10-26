<?php
declare(strict_types=1);
$CFG = require __DIR__ . '/config.php';
require_once __DIR__ . '/schema.php';

function cfg(string $k, $d = null) { global $CFG; return $CFG[$k] ?? $d; }

function json_out(array $d, int $code = 200): never {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store');
  echo json_encode($d, JSON_UNESCAPED_UNICODE);
  exit;
}
function fail(string $msg, int $code = 400, array $extra = []): never { json_out(['ok' => false, 'error' => $msg] + $extra, $code); }

function db(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;
  $f = cfg('db_file');
  if (!is_dir(dirname($f))) mkdir(dirname($f), 0750, true);
  $pdo = new PDO('sqlite:' . $f);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
  $pdo->exec("CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_type TEXT NOT NULL,
    first_name TEXT NOT NULL, last_name TEXT NOT NULL,
    mobile TEXT UNIQUE, email TEXT UNIQUE,
    mobile_verified INTEGER NOT NULL DEFAULT 0,
    email_verified INTEGER NOT NULL DEFAULT 0,
    business_name TEXT, description TEXT,
    created_at INTEGER NOT NULL)");
  $pdo->exec("CREATE TABLE IF NOT EXISTS otps(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL, channel TEXT NOT NULL, purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
    tries INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
    ip TEXT, created_at INTEGER NOT NULL)");
  $pdo->exec("CREATE TABLE IF NOT EXISTS works(
    id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, title TEXT NOT NULL,
    description TEXT, file TEXT, media_type TEXT, url TEXT, created_at INTEGER NOT NULL)");
  $pdo->exec("CREATE TABLE IF NOT EXISTS ads(
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, file TEXT NOT NULL, url TEXT, created_at INTEGER NOT NULL)");
  $pdo->exec("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)");
  $pdo->exec("CREATE INDEX IF NOT EXISTS otps_target ON otps(target, created_at)");
  return $pdo;
}

function fa2en(string $s): string {
  return strtr($s, ['۰'=>'0','۱'=>'1','۲'=>'2','۳'=>'3','۴'=>'4','۵'=>'5','۶'=>'6','۷'=>'7','۸'=>'8','۹'=>'9',
                    '٠'=>'0','١'=>'1','٢'=>'2','٣'=>'3','٤'=>'4','٥'=>'5','٦'=>'6','٧'=>'7','٨'=>'8','٩'=>'9']);
}
function norm_mobile(string $m): ?string {
  $m = preg_replace('/[\s\-()]/u', '', fa2en($m));
  $m = preg_replace('/^(\+98|0098|98)/', '0', $m);
  return preg_match('/^09\d{9}$/', $m) ? $m : null;
}
function norm_email(string $e): ?string {
  $e = mb_strtolower(trim($e));
  return filter_var($e, FILTER_VALIDATE_EMAIL) ? $e : null;
}
function clean(string $s, int $max): string {
  $s = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $s));
  return mb_substr($s, 0, $max);
}
function client_ip(): string { return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; }

function start_session(): void {
  if (session_status() === PHP_SESSION_ACTIVE) return;
  $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
  session_name('pcm_sid');
  session_set_cookie_params(['lifetime' => 60*60*24*14, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Lax']);
  session_start();
}
function current_user(): ?array {
  start_session();
  if (empty($_SESSION['uid'])) return null;
  $st = db()->prepare('SELECT * FROM users WHERE id=?'); $st->execute([$_SESSION['uid']]);
  return $st->fetch() ?: null;
}
function public_user(array $u): array {
  return [
    'id' => (int)$u['id'], 'account_type' => $u['account_type'],
    'first_name' => $u['first_name'], 'last_name' => $u['last_name'],
    'mobile' => $u['mobile'], 'email' => $u['email'],
    'mobile_verified' => (bool)$u['mobile_verified'], 'email_verified' => (bool)$u['email_verified'],
    'business_name' => $u['business_name'], 'description' => $u['description'],
  ];
}

// ---------- OTP ----------
function otp_hash(string $target, string $code): string {
  return hash_hmac('sha256', $target . '|' . $code, cfg('secret'));
}
function send_otp(string $target, string $channel, string $purpose): array {
  $db = db(); $now = time(); $ip = client_ip();
  $st = $db->prepare('SELECT COUNT(*) c, MAX(created_at) last FROM otps WHERE target=? AND created_at>?');
  $st->execute([$target, $now - 3600]); $r = $st->fetch();
  if ($r['last'] && $now - (int)$r['last'] < cfg('otp_resend'))
    fail('لطفاً کمی صبر کنید و دوباره تلاش کنید.', 429, ['wait' => cfg('otp_resend') - ($now - (int)$r['last'])]);
  if ((int)$r['c'] >= cfg('otp_hourly')) fail('تعداد درخواست کد زیاد است. بعداً دوباره تلاش کنید.', 429);
  $st = $db->prepare('SELECT COUNT(*) FROM otps WHERE ip=? AND created_at>?'); $st->execute([$ip, $now - 3600]);
  if ((int)$st->fetchColumn() >= cfg('ip_hourly')) fail('تعداد درخواست‌ها از این شبکه زیاد است. بعداً تلاش کنید.', 429);

  $code = (string)random_int(100000, 999999);
  $db->prepare('UPDATE otps SET used=1 WHERE target=? AND used=0')->execute([$target]);
  $db->prepare('INSERT INTO otps(target,channel,purpose,code_hash,expires_at,ip,created_at) VALUES(?,?,?,?,?,?,?)')
     ->execute([$target, $channel, $purpose, otp_hash($target, $code), $now + cfg('otp_ttl'), $ip, $now]);

  $out = ['ttl' => cfg('otp_ttl'), 'resend' => cfg('otp_resend')];
  if (cfg('dev_mode')) { $out['dev_code'] = $code; return $out; }
  $sent = $channel === 'sms' ? send_sms($target, $code) : send_email($target, $code);
  if (!$sent) fail('ارسال کد با خطا روبه‌رو شد. چند دقیقه بعد دوباره تلاش کنید.', 502);
  return $out;
}
function send_sms(string $mobile, string $code): bool {
  $s = cfg('sms');
  if (empty($s['api_key']) || empty($s['template'])) return false;
  $url = 'https://api.kavenegar.com/v1/' . rawurlencode($s['api_key']) . '/verify/lookup.json?' .
         http_build_query(['receptor' => $mobile, 'token' => $code, 'template' => $s['template']]);
  $ctx = stream_context_create(['http' => ['timeout' => 10, 'ignore_errors' => true]]);
  $res = @file_get_contents($url, false, $ctx);
  $j = $res ? json_decode($res, true) : null;
  return is_array($j) && (($j['return']['status'] ?? 0) === 200);
}
function send_email(string $to, string $code): bool {
  $m = cfg('mail');
  $subject = '=?UTF-8?B?' . base64_encode('کد تأیید خدمات فنی محمد') . '?=';
  $body = "<div dir='rtl' style='font-family:Tahoma,Arial;line-height:2'>کد تأیید شما: <b style='font-size:22px;letter-spacing:4px'>$code</b><br>این کد تا " .
          (cfg('otp_ttl') / 60) . " دقیقه معتبر است. اگر شما درخواست نکرده‌اید، این ایمیل را نادیده بگیرید.</div>";
  $h = "MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\nFrom: =?UTF-8?B?" . base64_encode($m['from_name']) . "?= <{$m['from']}>\r\n";
  return @mail($to, $subject, $body, $h);
}
function check_otp(string $target, string $code, string $purpose): bool {
  $db = db(); $now = time();
  $st = $db->prepare('SELECT * FROM otps WHERE target=? AND used=0 ORDER BY id DESC LIMIT 1');
  $st->execute([$target]); $o = $st->fetch();
  if (!$o || $o['purpose'] !== $purpose || $o['expires_at'] < $now) fail('کد منقضی شده است. کد جدید بگیرید.', 400, ['expired' => true]);
  if ((int)$o['tries'] >= cfg('otp_max_try')) { $db->prepare('UPDATE otps SET used=1 WHERE id=?')->execute([$o['id']]); fail('تعداد تلاش بیش از حد مجاز است. کد جدید بگیرید.', 400, ['expired' => true]); }
  $db->prepare('UPDATE otps SET tries=tries+1 WHERE id=?')->execute([$o['id']]);
  if (!hash_equals($o['code_hash'], otp_hash($target, fa2en(trim($code))))) fail('کد واردشده درست نیست.');
  $db->prepare('UPDATE otps SET used=1 WHERE id=?')->execute([$o['id']]);
  return true;
}

// ---------- مدیر ----------
function is_admin(?array $u): bool {
  if (!$u) return false;
  $a = cfg('admins', []);
  foreach ($a as $x) {
    $m = norm_mobile((string)$x); $e = norm_email((string)$x);
    if ($m && $u['mobile'] === $m && $u['mobile_verified']) return true;
    if ($e && $u['email'] === $e && $u['email_verified']) return true;
  }
  return false;
}
function require_admin(): array {
  if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'fetch') fail('درخواست نامعتبر', 403);
  $u = current_user();
  if (!$u) fail('وارد نشده‌اید.', 401);
  if (!is_admin($u)) fail('دسترسی مدیر ندارید.', 403);
  return $u;
}
const WORK_CATEGORIES = ['web', 'instagram', 'poster', 'channel', 'content', 'video'];
function safe_ext_url(?string $u): ?string {
  $u = trim((string)$u);
  return ($u !== '' && preg_match('#^https?://#i', $u) && mb_strlen($u) <= 500) ? $u : null;
}
/** ذخیره فایل آپلودشده در uploads/ و برگرداندن [مسیر، نوع] */
function save_upload(string $field, bool $allowVideo): array {
  if (empty($_FILES[$field]) || $_FILES[$field]['error'] === UPLOAD_ERR_NO_FILE) return [null, null];
  $f = $_FILES[$field];
  if ($f['error'] === UPLOAD_ERR_INI_SIZE || $f['error'] === UPLOAD_ERR_FORM_SIZE) fail('حجم فایل از حد مجاز هاست بیشتر است.');
  if ($f['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'])) fail('آپلود فایل ناموفق بود.');
  $mime = (new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);
  $img = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp', 'image/gif' => 'gif'];
  $vid = ['video/mp4' => 'mp4', 'video/webm' => 'webm'];
  if (isset($img[$mime])) { $ext = $img[$mime]; $type = 'image'; $max = 8 * 1024 * 1024; }
  elseif ($allowVideo && isset($vid[$mime])) { $ext = $vid[$mime]; $type = 'video'; $max = 60 * 1024 * 1024; }
  else fail($allowVideo ? 'فقط عکس (JPG، PNG، WebP) یا ویدیو (MP4، WebM) مجاز است.' : 'فقط عکس (JPG، PNG، WebP) مجاز است.');
  if ($f['size'] > $max) fail('حجم فایل بیش از حد مجاز است (عکس ۸ مگابایت، ویدیو ۶۰ مگابایت).');
  $dir = __DIR__ . '/../uploads';
  if (!is_dir($dir)) mkdir($dir, 0755, true);
  $name = bin2hex(random_bytes(12)) . '.' . $ext;
  if (!move_uploaded_file($f['tmp_name'], "$dir/$name")) fail('ذخیره فایل ناموفق بود. دسترسی پوشه uploads را بررسی کنید.', 500);
  return ['uploads/' . $name, $type];
}
function delete_upload(?string $rel): void {
  if ($rel && preg_match('#^uploads/[a-f0-9]{24}\.(jpg|png|webp|gif|mp4|webm)$#', $rel)) @unlink(__DIR__ . '/../' . $rel);
}

// ---------- تنظیمات و فهرست‌های قابل ویرایش ----------
function get_settings(): array {
  $out = [];
  foreach (db()->query('SELECT k,v FROM settings')->fetchAll() as $r) {
    if ($r['k'] === 'list.services' || $r['k'] === 'list.faq') continue;
    if (isset(SETTING_KEYS[$r['k']])) $out[$r['k']] = $r['v'];
  }
  return $out;
}
function get_lists(): array {
  $out = ['services' => null, 'faq' => null];
  foreach (['services', 'faq'] as $n) {
    $st = db()->prepare('SELECT v FROM settings WHERE k=?'); $st->execute(['list.' . $n]);
    $v = $st->fetchColumn();
    if ($v) { $j = json_decode($v, true); if (is_array($j)) $out[$n] = $j; }
  }
  return $out;
}
function valid_setting(string $key, string $val): string {
  [$type, $max] = SETTING_KEYS[$key];
  $val = $type === 'textarea' ? trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $val)) : clean($val, $max);
  if (mb_strlen($val) > $max) fail('متن «' . $key . '» بیش از حد طولانی است.');
  if ($type === 'handle') {
    $val = ltrim($val, '@ ');
    if ($val !== '' && !preg_match('/^[A-Za-z0-9_.]{3,40}$/', $val)) fail('آیدی باید فقط حروف انگلیسی، عدد، _ و . باشد (بدون @ و فاصله).');
  }
  return $val;
}
