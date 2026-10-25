<?php
declare(strict_types=1);
// آپلود نمونه کار و تبلیغ (فرم چندبخشی) — فقط مدیر
require __DIR__ . '/lib.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail('متد نامعتبر', 405);
require_admin();
$action = (string)($_POST['action'] ?? '');

if ($action === 'work_add') {
  $cat = (string)($_POST['category'] ?? '');
  if (!in_array($cat, WORK_CATEGORIES, true)) fail('دسته را انتخاب کنید.');
  $title = clean((string)($_POST['title'] ?? ''), 120);
  if ($title === '') fail('عنوان را وارد کنید.');
  $desc = clean((string)($_POST['description'] ?? ''), 600);
  $url = safe_ext_url($_POST['url'] ?? '');
  if (!empty($_POST['url']) && !$url) fail('لینک باید با https:// شروع شود.');
  [$file, $type] = save_upload('file', true);
  if (!$file && !$url) fail('حداقل یک عکس/ویدیو یا یک لینک اضافه کنید.');
  db()->prepare('INSERT INTO works(category,title,description,file,media_type,url,created_at) VALUES(?,?,?,?,?,?,?)')
     ->execute([$cat, $title, $desc, $file, $type, $url, time()]);
  json_out(['ok' => true]);
}
if ($action === 'ad_add') {
  $title = clean((string)($_POST['title'] ?? ''), 120);
  if ($title === '') fail('عنوان تبلیغ را وارد کنید.');
  $url = safe_ext_url($_POST['url'] ?? '');
  if (!empty($_POST['url']) && !$url) fail('لینک باید با https:// شروع شود.');
  [$file] = save_upload('file', false);
  if (!$file) fail('عکس پوستر یا بنر را انتخاب کنید.');
  db()->prepare('INSERT INTO ads(title,file,url,created_at) VALUES(?,?,?,?)')->execute([$title, $file, $url, time()]);
  json_out(['ok' => true]);
}
fail('عملیات نامعتبر', 404);
