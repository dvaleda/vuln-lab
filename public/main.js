console.log('main.js loaded');

document.addEventListener('DOMContentLoaded', () => {
  const sqliCheckbox = document.getElementById('sqli-enabled');
  const sqliStatus = document.getElementById('sqli-status');
  const sqliButton = document.getElementById('sqli-submit');
  const sqliOutput = document.getElementById('sqli-output');
  const sqliMsg = document.getElementById('sqli-msg');

  const authCheckbox = document.getElementById('auth-enabled');
  const authStatus = document.getElementById('auth-status');
  const authButton = document.getElementById('auth-submit');
  const authOutput = document.getElementById('auth-output');
  const authUser = document.getElementById('auth-user');
  const authPass = document.getElementById('auth-pass');

  function updSqli() { sqliStatus.textContent = sqliCheckbox.checked ? 'Ranjivost uključena' : 'Ranjivost isključena'; }
  function updAuth() { if (authStatus) authStatus.textContent = authCheckbox.checked ? 'Ranjivost uključena' : 'Ranjivost isključena'; }
  updSqli(); updAuth();
  sqliCheckbox.addEventListener('change', updSqli);
  authCheckbox && authCheckbox.addEventListener('change', updAuth);

  // print JSON
  function showJSON(el, obj) {
    try { el.textContent = JSON.stringify(obj, null, 2); } catch (e) { el.textContent = String(obj); }
  }

  // SQLi /search/query
  sqliButton.addEventListener('click', async () => {
    sqliOutput.textContent = 'Kontaktiram server...';
    const msg = (sqliMsg && sqliMsg.value) || '';
    const mode = sqliCheckbox.checked ? 'vuln' : 'safe';

    try {
      const body = new URLSearchParams({ msg, mode });
      const res = await fetch('/search/query', { method: 'POST', body });
      if (!res.ok) {
        // read error detail
        let errText = `Server returned ${res.status}`;
        try { const j = await res.json(); if (j && j.error) errText += ` — ${j.error}`; } catch (_) {}
        sqliOutput.textContent = errText;
        return;
      }
      const data = await res.json();
      showJSON(sqliOutput, data);
      console.log('/search/query response', data);
    } catch (err) {
      sqliOutput.textContent = 'Greška u komunikaciji sa serverom: ' + err;
      console.warn(err);
    }
  });

  // auth /auth/login
  if (authButton && authUser && authPass && authOutput) {
    authButton.addEventListener('click', async () => {
      authOutput.textContent = 'Kontaktiram server...';
      const username = (authUser.value || '').trim();
      const password = (authPass.value || '').trim();
      const mode = authCheckbox.checked ? 'vuln' : 'safe';

      try {
        const body = new URLSearchParams({ username, password, mode });
        // cookie set by server will be stored by browser automatically
        const res = await fetch('/auth/login', { method: 'POST', body, credentials: 'same-origin' });
        // credentials, same-origin for browser to store cookies from same host
        if (!res.ok) {
          let errText = `Server returned ${res.status}`;
          try { const j = await res.json(); if (j && j.message) errText += ` — ${j.message}`; } catch(_) {}
          authOutput.textContent = errText;
          return;
        }
        const data = await res.json();
        // server response
        showJSON(authOutput, data);

        // show document.cookie if vuln
        try {
          const cookieStr = document.cookie || '(no readable cookies)';
          authOutput.textContent += '\n\n// document.cookie:\n' + cookieStr;
        } catch (e) {
          // ignore
        }
        console.log('/auth/login response', data);
      } catch (err) {
        authOutput.textContent = 'Greška u komunikaciji sa serverom: ' + err;
        console.warn(err);
      }
    });
  }

});