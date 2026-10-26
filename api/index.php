<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail('متد نامعتبر', 405);
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) fail('درخواست نامعتبر', 415);
$in = json_decode(file_get_contents('php://input') ?: '', true);
if (!is_array($in)) fail('درخواست نامعتبر');
$action = (string)($in['action'] ?? '');

// خدمات نمونه — بعداً با جزئیاتی که محمد می‌دهد کامل می‌شود
function services_for(string $type): array {
  $biz = [
    ['id' => 'lottery', 'title' => 'قرعه‌کشی', 'desc' => 'برگزاری قرعه‌کشی برای فروشگاه یا برند شما', 'status' => 'soon'],
    ['id' => 'design',  'title' => 'طراحی (لوگو، پوستر، بنر)', 'desc' => 'طراحی هویت بصری و تبلیغاتی کسب‌وکار', 'status' => 'soon'],
  ];
  $cus = [
    ['id' => 'personal', 'title' => 'خدمات شخصی', 'desc' => 'خدمات ویژه افراد عادی', 'status' => 'soon'],
  ];
  return $type === 'business' ? $biz : $cus;
}

switch ($action) {
  case 'signup': {
    $type = $in['account_type'] ?? '';
    if (!in_array($type, ['business', 'customer'], true)) fail('نوع حساب را انتخاب کنید.');
    $fn = clean((string)($in['first_name'] ?? ''), 60); $ln = clean((string)($in['last_name'] ?? ''), 60);
    if ($fn === '' || $ln === '') fail('نام و نام خانوادگی را وارد کنید.');
    $mobile = norm_mobile((string)($in['mobile'] ?? '')); if (!$mobile) fail('شماره موبایل معتبر نیست (مثال: 09123456789).');
    $email = norm_email((string)($in['email'] ?? '')); if (!$email) fail('ایمیل معتبر نیست.');
    $channel = ($in['channel'] ?? '') === 'email' ? 'email' : 'sms';
    $biz = $type === 'business' ? clean((string)($in['business_name'] ?? ''), 120) : null;
    if ($type === 'business' && !$biz) fail('نام فروشگاه یا برند را وارد کنید.');
    $desc = clean((string)($in['description'] ?? ''), 1000);
    if (empty($in['accept_terms'])) fail('پذیرش قوانین الزامی است.');

    $db = db();
    $st = $db->prepare('SELECT * FROM users WHERE mobile=? OR email=?'); $st->execute([$mobile, $email]);
    $ex = $st->fetchAll();
    foreach ($ex as $u) if ($u['mobile_verified'] || $u['email_verified'])
      fail('با این شماره یا ایمیل قبلاً ثبت‌نام شده است. از بخش «ورود» استفاده کنید.', 409);
    if (count($ex) > 1) fail('این شماره یا ایمیل قبلاً استفاده شده است.', 409);
    if ($ex) {
      $db->prepare('UPDATE users SET account_type=?,first_name=?,last_name=?,mobile=?,email=?,business_name=?,description=? WHERE id=?')
         ->execute([$type, $fn, $ln, $mobile, $email, $biz, $desc, $ex[0]['id']]);
    } else {
      $db->prepare('INSERT INTO users(account_type,first_name,last_name,mobile,email,business_name,description,created_at) VALUES(?,?,?,?,?,?,?,?)')
         ->execute([$type, $fn, $ln, $mobile, $email, $biz, $desc, time()]);
    }
    $target = $channel === 'sms' ? $mobile : $email;
    $r = send_otp($target, $channel, 'signup');
    json_out(['ok' => true, 'channel' => $channel, 'target' => $target] + $r);
  }

  case 'login': {
    $id = trim((string)($in['identifier'] ?? ''));
    $mobile = norm_mobile($id); $email = $mobile ? null : norm_email($id);
    if (!$mobile && !$email) fail('شماره موبایل یا ایمیل معتبر وارد کنید.');
    $st = db()->prepare($mobile ? 'SELECT * FROM users WHERE mobile=?' : 'SELECT * FROM users WHERE email=?');
    $st->execute([$mobile ?: $email]); $u = $st->fetch();
    // پاسخ یکسان برای کاربر موجود/ناموجود تا شماره‌ها لو نروند؛ فقط برای کاربر موجود کد ارسال می‌شود
    $channel = $mobile ? 'sms' : 'email'; $target = $mobile ?: $email;
    if (!$u || !($mobile ? $u['mobile_verified'] : $u['email_verified'])) {
      json_out(['ok' => true, 'channel' => $channel, 'target' => $target, 'ttl' => cfg('otp_ttl'), 'resend' => cfg('otp_resend')]);
    }
    $r = send_otp($target, $channel, 'login');
    json_out(['ok' => true, 'channel' => $channel, 'target' => $target] + $r);
  }

  case 'resend': {
    $target = (string)($in['target'] ?? ''); $purpose = ($in['purpose'] ?? '') === 'signup' ? 'signup' : 'login';
    $channel = norm_mobile($target) ? 'sms' : 'email';
    $target = $channel === 'sms' ? norm_mobile($target) : norm_email($target);
    if (!$target) fail('درخواست نامعتبر');
    $st = db()->prepare($channel === 'sms' ? 'SELECT id FROM users WHERE mobile=?' : 'SELECT id FROM users WHERE email=?');
    $st->execute([$target]);
    if (!$st->fetch()) json_out(['ok' => true, 'ttl' => cfg('otp_ttl'), 'resend' => cfg('otp_resend')]);
    json_out(['ok' => true] + send_otp($target, $channel, $purpose));
  }

  case 'verify': {
    $target = (string)($in['target'] ?? ''); $purpose = ($in['purpose'] ?? '') === 'signup' ? 'signup' : 'login';
    $channel = norm_mobile($target) ? 'sms' : 'email';
    $target = $channel === 'sms' ? norm_mobile($target) : norm_email($target);
    if (!$target) fail('درخواست نامعتبر');
    check_otp($target, (string)($in['code'] ?? ''), $purpose);
    $col = $channel === 'sms' ? 'mobile' : 'email';
    $st = db()->prepare("SELECT * FROM users WHERE $col=?"); $st->execute([$target]); $u = $st->fetch();
    if (!$u) fail('حساب پیدا نشد.', 404);
    db()->prepare('UPDATE users SET ' . ($channel === 'sms' ? 'mobile_verified' : 'email_verified') . '=1 WHERE id=?')->execute([$u['id']]);
    start_session(); session_regenerate_id(true); $_SESSION['uid'] = (int)$u['id'];
    $st = db()->prepare('SELECT * FROM users WHERE id=?'); $st->execute([$u['id']]);
    json_out(['ok' => true, 'user' => public_user($st->fetch())]);
  }

  case 'me': {
    $u = current_user();
    if (!$u) fail('وارد نشده‌اید.', 401);
    json_out(['ok' => true, 'user' => public_user($u), 'services' => services_for($u['account_type'])]);
  }

  case 'update_profile': {
    $u = current_user(); if (!$u) fail('وارد نشده‌اید.', 401);
    $fn = clean((string)($in['first_name'] ?? ''), 60); $ln = clean((string)($in['last_name'] ?? ''), 60);
    if ($fn === '' || $ln === '') fail('نام و نام خانوادگی را وارد کنید.');
    $biz = $u['account_type'] === 'business' ? clean((string)($in['business_name'] ?? ''), 120) : null;
    if ($u['account_type'] === 'business' && !$biz) fail('نام فروشگاه یا برند را وارد کنید.');
    db()->prepare('UPDATE users SET first_name=?,last_name=?,business_name=?,description=? WHERE id=?')
        ->execute([$fn, $ln, $biz, clean((string)($in['description'] ?? ''), 1000), $u['id']]);
    $u = current_user(); json_out(['ok' => true, 'user' => public_user($u)]);
  }

  case 'logout': {
    start_session(); $_SESSION = []; session_destroy();
    json_out(['ok' => true]);
  }

  case 'public_content': {
    $db = db();
    $w = $db->query('SELECT id,category,title,description,file,media_type,url FROM works ORDER BY id DESC')->fetchAll();
    $a = $db->query('SELECT id,title,file,url FROM ads ORDER BY id DESC')->fetchAll();
    json_out(['ok' => true, 'works' => $w, 'ads' => $a, 'settings' => get_settings(), 'lists' => get_lists()]);
  }

  case 'admin_me': {
    $u = current_user();
    json_out(['ok' => true, 'logged_in' => (bool)$u, 'is_admin' => is_admin($u)]);
  }

  case 'work_delete': {
    require_admin(); $id = (int)($in['id'] ?? 0);
    $st = db()->prepare('SELECT file FROM works WHERE id=?'); $st->execute([$id]); $r = $st->fetch();
    if ($r) { delete_upload($r['file']); db()->prepare('DELETE FROM works WHERE id=?')->execute([$id]); }
    json_out(['ok' => true]);
  }

  case 'ad_delete': {
    require_admin(); $id = (int)($in['id'] ?? 0);
    $st = db()->prepare('SELECT file FROM ads WHERE id=?'); $st->execute([$id]); $r = $st->fetch();
    if ($r) { delete_upload($r['file']); db()->prepare('DELETE FROM ads WHERE id=?')->execute([$id]); }
    json_out(['ok' => true]);
  }

  case 'settings_get': {
    require_admin();
    json_out(['ok' => true, 'settings' => get_settings(), 'lists' => get_lists()]);
  }

  case 'settings_save': {
    require_admin();
    $vals = $in['values'] ?? null; if (!is_array($vals)) fail('درخواست نامعتبر');
    $db = db(); $db->beginTransaction();
    foreach ($vals as $k => $v) {
      if (!is_string($k) || !isset(SETTING_KEYS[$k]) || !is_string($v)) { $db->rollBack(); fail('فیلد نامعتبر.'); }
      $v = valid_setting($k, $v);
      if ($v === '') $db->prepare('DELETE FROM settings WHERE k=?')->execute([$k]);   // خالی = بازگشت به پیش‌فرض
      else $db->prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')->execute([$k, $v]);
    }
    $db->commit();
    json_out(['ok' => true, 'settings' => get_settings()]);
  }

  case 'list_save': {
    require_admin();
    $name = (string)($in['name'] ?? ''); if (!in_array($name, ['services', 'faq'], true)) fail('فهرست نامعتبر.');
    $items = $in['items'] ?? null;
    if ($items === null) { db()->prepare('DELETE FROM settings WHERE k=?')->execute(['list.' . $name]); json_out(['ok' => true, 'reset' => true]); }
    if (!is_array($items) || count($items) < 1 || count($items) > 30) fail('تعداد موارد باید بین ۱ تا ۳۰ باشد.');
    $clean = [];
    foreach ($items as $it) {
      if (!is_array($it)) fail('داده نامعتبر.');
      if ($name === 'services') {
        $t = clean((string)($it['title'] ?? ''), 80); $d = clean((string)($it['desc'] ?? ''), 300); $l = clean((string)($it['link'] ?? ''), 40);
        $ic = in_array($it['icon'] ?? '', SERVICE_ICONS, true) ? $it['icon'] : 'star';
        if ($t === '') fail('عنوان هر خدمت الزامی است.');
        $clean[] = ['icon' => $ic, 'title' => $t, 'desc' => $d, 'link' => $l !== '' ? $l : 'ثبت سفارش'];
      } else {
        $q = clean((string)($it['q'] ?? ''), 200); $a = clean((string)($it['a'] ?? ''), 800);
        if ($q === '' || $a === '') fail('سؤال و پاسخ هر مورد الزامی است.');
        $clean[] = ['q' => $q, 'a' => $a];
      }
    }
    db()->prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')->execute(['list.' . $name, json_encode($clean, JSON_UNESCAPED_UNICODE)]);
    json_out(['ok' => true, 'items' => $clean]);
  }

  case 'users_list': {
    require_admin();
    $rows = db()->query('SELECT id,account_type,first_name,last_name,mobile,email,mobile_verified,email_verified,business_name,description,created_at FROM users ORDER BY id DESC LIMIT 500')->fetchAll();
    foreach ($rows as &$r) { $r['is_admin'] = is_admin($r); } unset($r);
    json_out(['ok' => true, 'users' => $rows]);
  }

  case 'user_delete': {
    $me = require_admin(); $id = (int)($in['id'] ?? 0);
    if ($id === (int)$me['id']) fail('حساب خودتان را نمی‌توانید حذف کنید.');
    db()->prepare('DELETE FROM users WHERE id=?')->execute([$id]);
    json_out(['ok' => true]);
  }

  default: fail('عملیات نامعتبر', 404);
}
