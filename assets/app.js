// کمک‌تابع‌های مشترک صفحه‌های ثبت‌نام و پنل
const API = 'api/';
async function api(action, data = {}) {
  let res;
  try {
    res = await fetch(API, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, ...data }) });
  } catch (e) { return { ok: false, error: 'ارتباط با سرور برقرار نشد.' }; }
  try { return await res.json(); } catch (e) { return { ok: false, error: 'پاسخ نامعتبر از سرور.' }; }
}
const $ = (s, r = document) => r.querySelector(s);
function show(el, text, kind) { el.className = 'msg ' + kind; el.textContent = text; }
function clearMsg(el) { el.className = 'msg'; el.textContent = ''; }
const FA = '۰۱۲۳۴۵۶۷۸۹';
const toFa = s => String(s).replace(/\d/g, d => FA[d]);
function escapeText(s) { const d = document.createElement('div'); d.textContent = s ?? ''; return d.innerHTML; }
