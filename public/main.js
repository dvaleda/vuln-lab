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
  function renderRows(el, data, mode) {
    if (!el) return;
    if (!data || !Array.isArray(data.rows)) {
      el.textContent = 'nema rezultata';
      return;
    }
    if (mode === 'safe') {
      const rows = data.rows;
      if (rows.length === 0) {
        el.textContent = 'Nema podataka za zadani upit.';
        return;
      }
      const header = `Prikaz rezultata\n\n`;
      const lines = rows.map(r => `id: ${r.id}  |  content: ${r.content}`);
      el.textContent = header + lines.join('\n');
      return;
  }

  if (mode === 'vuln') {
    try {
      el.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      el.textContent = String(data);
    }
    return;
  }
  // fallback
  el.textContent = JSON.stringify(data, null, 2);
}

  // SQLi /search/query
  sqliButton.addEventListener('click', async () => {
    const msg = (sqliMsg && sqliMsg.value) || '';
    const mode = sqliCheckbox.checked ? 'vuln' : 'safe';
    const pin = (document.getElementById('pin')?.value || '');

    try {
      const body = new URLSearchParams({ msg, mode, pin });
      const res = await fetch('/search/query', { method: 'POST', body });
      if (!res.ok) {
        // read error detail
        let errText = `Server returned ${res.status}`;
        try { const j = await res.json(); if (j && j.error) errText += ` — ${j.error}`; } catch (_) {}
        sqliOutput.textContent = errText;
        return;
      }
      const data = await res.json();
      renderRows(sqliOutput, data, data.mode || mode);
      console.log('/search/query response', data);
    } catch (err) {
      sqliOutput.textContent = 'Greška u komunikaciji sa serverom: ' + err;
      console.warn(err);
    }
  });

  // auth /auth/login
  if (authButton && authUser && authPass && authOutput) {
    authButton.addEventListener('click', async () => {
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
          try { const j = await res.json(); if (j && j.message) errText += ` ${j.message}`; } catch(_) {}
          authOutput.textContent = errText;
          return;
        }
        const data = await res.json();
        // server response
        try {
          if (data && data.message) {
            authOutput.textContent = data.message;
          } else {
            authOutput.textContent = JSON.stringify(data, null, 2);
          }
        } catch (e) {
          authOutput.textContent = String(data);
        }

        // show document.cookie if vuln
        try {
          const cookieStr = document.cookie || '(no readable cookies)';
          if (mode == 'vuln') { alert('Cookie readable in VULN mode \n' + cookieStr); }
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