/* ================================================================
   AYC Portal — Shared JS Utilities
   Loaded on every protected page via base.html
   ================================================================ */

/** Escape HTML to prevent XSS when inserting user data into the DOM. */
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── CSRF token ────────────────────────────────────────────────────────────────
// Read once from the <meta name="csrf-token"> tag rendered by base.html.
// The token is re-read on every call so it stays fresh after Turbo/PJAX
// navigation (if ever adopted), but for now the meta tag is static per page.
function _getCsrfToken() {
  const el = document.querySelector('meta[name="csrf-token"]');
  return el ? el.getAttribute('content') : '';
}

/**
 * Wrapper around fetch for API calls.
 * - Automatically sends X-CSRFToken on every state-changing request.
 * - Automatically redirects to / on 401 (session expired / token rotated).
 * - Returns the parsed JSON body, or throws on non-2xx.
 * - When body is FormData, does NOT set Content-Type so the browser
 *   can add the correct multipart boundary automatically.
 */
async function apiFetch(url, options = {}) {
  const method      = (options.method || 'GET').toUpperCase();
  const isFormData  = options.body instanceof FormData;
  const isMutating  = !['GET', 'HEAD', 'OPTIONS'].includes(method);

  const baseHeaders = isFormData ? {} : { 'Content-Type': 'application/json' };
  if (isMutating) baseHeaders['X-CSRFToken'] = _getCsrfToken();

  const res = await fetch(url, {
    credentials: 'same-origin',
    ...options,
    headers: { ...baseHeaders, ...(options.headers || {}) },
  });
  if (res.status === 401) {
    window.location.href = '/';
    return;
  }
  // Guard against non-JSON responses (e.g. Flask 500 HTML error pages).
  // res.json() throws a parse error in some browsers with a cryptic message
  // ("The string did not match the expected pattern" in Safari) — catch it
  // and surface a cleaner HTTP status message instead.
  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error(`Server error (HTTP ${res.status}) — check the app logs`);
  }
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

/**
 * Show a toast notification.
 * @param {string} msg   Message to display.
 * @param {boolean} err  If true, shows in red (error style).
 */
function showToast(msg, err = false) {
  let el = document.getElementById('_toast');
  if (!el) {
    el = document.createElement('div');
    el.id = '_toast';
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.toggle('err', err);
  el.classList.add('show');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove('show'), 3200);
}

/** Format a YYYY-MM-DD date string to DD/MM/YYYY for display. */
function fmtDate(val) {
  if (!val) return '—';
  const d = new Date(val);
  if (isNaN(d.getTime())) return val;
  const dd   = String(d.getUTCDate()).padStart(2, '0');
  const mm   = String(d.getUTCMonth() + 1).padStart(2, '0');
  const yyyy = d.getUTCFullYear();
  return `${dd}/${mm}/${yyyy}`;
}

/** Return val as a display string, replacing blank/null/NaN with '—'. */
function v(val) {
  const s = (val === null || val === undefined) ? '' : String(val).trim();
  return (s === '' || s.toLowerCase() === 'nan') ? '—' : s;
}

/** Sign the user out. */
async function doLogout() {
  // Use apiFetch so the CSRF token is included; ignore any error and redirect regardless.
  try { await apiFetch('/api/auth/logout', { method: 'POST' }); } catch (_) {}
  window.location.href = '/';
}
