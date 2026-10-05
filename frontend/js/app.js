(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  // Always escape server data before putting it in HTML (file names are user controlled -> XSS)
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtSize = b => b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(2) + ' MB';
  const fmtDate = s => s ? new Date(s + 'Z').toLocaleString() : '';

  let token = localStorage.getItem('sv_token');
  let me = null;
  let vaultToken = null, vaultTimer = null;
  const modal = new bootstrap.Modal('#modal');

  function toast(msg, type = 'success') {
    const d = document.createElement('div');
    d.className = `alert alert-${type} shadow-sm py-2 mb-2`;
    d.textContent = msg;
    $('#toast-area').appendChild(d);
    setTimeout(() => d.remove(), 4500);
  }

  async function api(path, { method = 'GET', body, form, raw } = {}) {
    const headers = {};
    if (token) headers.Authorization = 'Bearer ' + token;
    if (vaultToken) headers['X-Vault-Token'] = vaultToken;
    let payload;
    if (form) payload = form;
    else if (body) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
    const r = await fetch('/api' + path, { method, headers, body: payload });
    if (!r.ok) {
      let msg = 'Error ' + r.status;
      try {
        const j = await r.json();
        msg = typeof j.detail === 'string' ? j.detail : (j.detail || []).map(d => d.msg).join('; ');
      } catch { /* ignore */ }
      if (r.status === 401 && token && !path.startsWith('/auth/login')) { logout(); }
      if (r.status === 403 && /vault is locked/i.test(msg)) { lockVault(); }
      throw new Error(msg);
    }
    if (raw) return r;
    return r.status === 204 ? null : r.json();
  }

  async function saveBlob(path, name) {
    const r = await api(path, { raw: true });
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* ---------------- auth ---------------- */
  $$('[data-auth]').forEach(b => b.onclick = () => {
    $$('[data-auth]').forEach(x => x.classList.toggle('active', x === b));
    $('#login-form').classList.toggle('d-none', b.dataset.auth !== 'login');
    $('#register-form').classList.toggle('d-none', b.dataset.auth !== 'register');
    $('#auth-error').classList.add('d-none');
  });
  const authError = m => { const e = $('#auth-error'); e.textContent = m; e.classList.remove('d-none'); };

  $('#login-form').onsubmit = async e => {
    e.preventDefault();
    try {
      const d = await api('/auth/login', { method: 'POST', body: { username: $('#login-user').value.trim(), password: $('#login-pass').value } });
      token = d.access_token; localStorage.setItem('sv_token', token);
      $('#login-pass').value = '';
      await enterApp();
    } catch (err) { authError(err.message); }
  };
  $('#register-form').onsubmit = async e => {
    e.preventDefault();
    try {
      await api('/auth/register', { method: 'POST', body: { username: $('#reg-user').value.trim(), email: $('#reg-email').value.trim(), password: $('#reg-pass').value } });
      toast('Account created. You can sign in now.');
      $('[data-auth="login"]').click();
      $('#login-user').value = $('#reg-user').value; $('#reg-pass').value = '';
    } catch (err) { authError(err.message); }
  };
  function logout() {
    token = null; me = null; localStorage.removeItem('sv_token'); lockVault();
    $('#app-view').classList.add('d-none'); $('#auth-view').classList.remove('d-none');
  }
  $('#logout').onclick = logout;

  async function enterApp() {
    me = await api('/auth/me');
    $('#auth-view').classList.add('d-none'); $('#app-view').classList.remove('d-none');
    $('#who').textContent = `${me.username} (${me.role})`;
    $('#admin-nav').classList.toggle('d-none', me.role !== 'ADMIN');
    showTab('files');
  }
  async function refreshQuota() {
    me = await api('/auth/me');
    const pct = Math.min(100, me.used_bytes / me.quota_bytes * 100);
    $('#quota-text').textContent = `${fmtSize(me.used_bytes)} of ${fmtSize(me.quota_bytes)} used`;
    const bar = $('#quota-bar'); bar.style.width = pct + '%';
    bar.className = 'progress-bar ' + (pct > 90 ? 'bg-danger' : pct > 70 ? 'bg-warning' : 'bg-success');
  }

  /* ---------------- tabs ---------------- */
  const loaders = { files: loadFiles, vault: loadVault, trash: loadTrash, logs: loadLogs, admin: loadAdmin };
  function showTab(name) {
    $$('#main-nav [data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    $$('.tab-section').forEach(s => s.classList.toggle('d-none', s.id !== 'tab-' + name));
    refreshQuota().catch(() => { });
    loaders[name]().catch(err => toast(err.message, 'danger'));
  }
  $$('#main-nav [data-tab]').forEach(b => b.onclick = () => showTab(b.dataset.tab));

  /* ---------------- file tables ---------------- */
  function fileRow(f, mode) {
    let actions = '';
    const btn = (a, label, cls = 'outline-secondary') => `<button class="btn btn-sm btn-${cls}" data-act="${a}" data-id="${f.id}" data-name="${esc(f.name)}">${label}</button>`;
    if (mode === 'trash') actions = btn('restore', 'Restore', 'outline-success') + ' ' + btn('purge', 'Delete forever', 'outline-danger');
    else {
      actions = btn('download', 'Download') + ' ' + btn('versions', 'Versions');
      if (mode === 'files') actions += ' ' + btn('share', 'Share') + ' ' + btn('tovault', 'To vault');
      else actions += ' ' + btn('fromvault', 'Move out');
      actions += ' ' + btn('delete', 'Delete', 'outline-danger');
    }
    const when = mode === 'trash' ? fmtDate(f.deleted_at) : fmtDate(f.created_at);
    const ver = mode === 'trash' ? '' : `<td><span class="badge text-bg-light">v${f.version}</span></td>`;
    return `<tr><td class="file-name" title="${esc(f.name)}">${esc(f.name)}</td><td>${esc(f.category)}</td><td>${fmtSize(f.size)}</td>${ver}<td>${when}</td><td class="text-end text-nowrap">${actions}</td></tr>`;
  }
  const empty = (cols, text) => `<tr><td colspan="${cols}" class="text-center text-muted py-4">${text}</td></tr>`;

  async function loadFiles() {
    const qs = new URLSearchParams();
    if ($('#search').value) qs.set('q', $('#search').value);
    if ($('#cat').value) qs.set('category', $('#cat').value);
    const list = await api('/files?' + qs);
    $('#files-body').innerHTML = list.length ? list.map(f => fileRow(f, 'files')).join('') : empty(6, 'No files yet. Upload your first file above.');
  }
  let searchTimer;
  $('#search').oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => loadFiles().catch(e => toast(e.message, 'danger')), 300); };
  $('#cat').onchange = () => loadFiles().catch(e => toast(e.message, 'danger'));

  $('#upload-form').onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('file', $('#upload-file').files[0]);
    fd.append('allow_duplicate', $('#upload-dup').checked ? 'true' : 'false');
    try {
      await api('/files/upload', { method: 'POST', form: fd });
      toast('File uploaded'); e.target.reset(); showTab('files');
    } catch (err) { toast(err.message, 'danger'); }
  };

  async function loadTrash() {
    const list = await api('/trash');
    $('#trash-body').innerHTML = list.length ? list.map(f => fileRow(f, 'trash')).join('') : empty(5, 'The recycle bin is empty.');
  }

  async function loadLogs() {
    const rows = await api('/me/logs?limit=100');
    $('#logs-body').innerHTML = rows.map(r => `<tr><td>${fmtDate(r.created_at)}</td><td>${esc(r.action)}</td><td>${esc(r.detail)}</td><td>${esc(r.ip)}</td></tr>`).join('') || empty(4, 'No activity yet.');
  }

  /* ---------------- vault ---------------- */
  function lockVault() {
    vaultToken = null; clearTimeout(vaultTimer);
    if (me && !$('#tab-vault').classList.contains('d-none')) loadVault().catch(() => { });
  }
  async function loadVault() {
    const st = await api('/vault/status');
    const unlocked = !!vaultToken && st.unlocked;
    if (!unlocked) vaultToken = null;
    $('#vault-setup').classList.toggle('d-none', st.configured);
    $('#vault-locked').classList.toggle('d-none', !st.configured || unlocked);
    $('#vault-open').classList.toggle('d-none', !unlocked);
    if (unlocked) {
      const list = await api('/vault/files');
      $('#vault-body').innerHTML = list.length ? list.map(f => fileRow(f, 'vault')).join('') : empty(6, 'Your vault is empty.');
    }
  }
  $('#vault-setup-form').onsubmit = async e => {
    e.preventDefault();
    if ($('#setup-pin').value !== $('#setup-pin2').value) return toast('PINs do not match', 'danger');
    try {
      await api('/vault/setup', { method: 'POST', body: { pin: $('#setup-pin').value } });
      e.target.reset(); toast('Vault PIN created'); loadVault();
    } catch (err) { toast(err.message, 'danger'); }
  };
  $('#vault-unlock-form').onsubmit = async e => {
    e.preventDefault();
    try {
      const d = await api('/vault/unlock', { method: 'POST', body: { pin: $('#unlock-pin').value } });
      vaultToken = d.vault_token; e.target.reset();
      clearTimeout(vaultTimer); vaultTimer = setTimeout(() => { lockVault(); toast('Vault locked automatically', 'warning'); }, d.expires_in_minutes * 60000);
      loadVault();
    } catch (err) { toast(err.message, 'danger'); }
  };
  $('#vault-lock').onclick = () => { lockVault(); toast('Vault locked'); };
  $('#vault-upload-form').onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData(); fd.append('file', $('#vault-file').files[0]);
    try { await api('/vault/upload', { method: 'POST', form: fd }); toast('Saved to vault'); e.target.reset(); showTab('vault'); }
    catch (err) { toast(err.message, 'danger'); }
  };

  /* ---------------- row actions ---------------- */
  document.addEventListener('click', async e => {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const id = b.dataset.id, name = b.dataset.name, act = b.dataset.act;
    const tab = $$('#main-nav [data-tab]').find(x => x.classList.contains('active'))?.dataset.tab;
    try {
      if (act === 'download') await saveBlob(`/files/${id}/download`, name);
      else if (act === 'versions') await openVersions(id, name);
      else if (act === 'share') await openShare(id, name);
      else if (act === 'delete') { if (confirm(`Move "${name}" to the Recycle bin?`)) { await api(`/files/${id}`, { method: 'DELETE' }); toast('Moved to Recycle bin'); showTab(tab); } }
      else if (act === 'restore') { await api(`/trash/${id}/restore`, { method: 'POST' }); toast('File restored'); showTab('trash'); }
      else if (act === 'purge') { if (confirm(`Delete "${name}" forever? This cannot be undone.`)) { await api(`/trash/${id}`, { method: 'DELETE' }); toast('Deleted forever'); showTab('trash'); } }
      else if (act === 'tovault') {
        if (!vaultToken) { toast('Open the Secure vault tab and unlock it first', 'warning'); return; }
        await api(`/vault/files/${id}/move`, { method: 'POST', body: { to_vault: true } }); toast('Moved to vault'); showTab('files');
      }
      else if (act === 'fromvault') { await api(`/vault/files/${id}/move`, { method: 'POST', body: { to_vault: false } }); toast('Moved out of vault'); showTab('vault'); }
    } catch (err) { toast(err.message, 'danger'); }
  });

  /* ---------------- versions modal ---------------- */
  async function openVersions(id, name) {
    const d = await api(`/files/${id}/versions`);
    const rows = [`<tr class="table-success"><td>v${d.current.version} (current)</td><td>${esc(d.current.name)}</td><td>${fmtSize(d.current.size)}</td><td>${fmtDate(d.current.created_at)}</td><td></td></tr>`]
      .concat(d.versions.map(v => `<tr><td>v${v.version}</td><td>${esc(v.name)}</td><td>${fmtSize(v.size)}</td><td>${fmtDate(v.created_at)}</td>
        <td class="text-end"><button class="btn btn-sm btn-outline-primary" data-m="restore-version" data-n="${v.version}">Restore this version</button></td></tr>`));
    $('#modal-title').textContent = 'Versions of ' + name;
    $('#modal-body').innerHTML = `<table class="table table-sm"><thead><tr><th>Version</th><th>Name</th><th>Size</th><th>Saved</th><th></th></tr></thead><tbody>${rows.join('')}</tbody></table>
      <form id="ver-form" class="row g-2 mt-2"><div class="col-8"><input type="file" class="form-control" id="ver-file" required></div>
      <div class="col-4"><button class="btn btn-sv w-100">Upload new version</button></div></form>`;
    $('#modal-body').dataset.fid = id; $('#modal-body').dataset.fname = name;
    modal.show();
  }

  /* ---------------- share modal ---------------- */
  async function openShare(id, name) {
    const list = await api(`/files/${id}/shares`);
    const now = Date.now();
    const rows = list.map(s => {
      const expired = new Date(s.expires_at + 'Z') < now;
      const state = s.revoked ? 'revoked' : expired ? 'expired' : 'active';
      return `<tr><td>${esc(s.permission)}</td><td>${fmtDate(s.expires_at)}</td><td>${s.download_count}${s.max_downloads ? '/' + s.max_downloads : ''}</td><td>${state}</td>
        <td class="text-end">${state === 'active' ? `<button class="btn btn-sm btn-outline-danger" data-m="revoke" data-sid="${s.id}">Revoke</button>` : ''}</td></tr>`;
    }).join('') || '<tr><td colspan="5" class="text-muted text-center">No links yet.</td></tr>';
    $('#modal-title').textContent = 'Share ' + name;
    $('#modal-body').innerHTML = `<form id="share-form" class="row g-2 mb-3">
        <div class="col-md-3"><label class="form-label small">Permission</label><select id="sh-perm" class="form-select"><option value="download">Download</option><option value="view">View only</option></select></div>
        <div class="col-md-3"><label class="form-label small">Expires after</label><select id="sh-exp" class="form-select"><option value="15">15 minutes</option><option value="60" selected>1 hour</option><option value="1440">1 day</option><option value="10080">7 days</option></select></div>
        <div class="col-md-3"><label class="form-label small">Max downloads</label><input id="sh-max" type="number" min="1" max="1000" class="form-control" placeholder="Unlimited"></div>
        <div class="col-md-3 d-flex align-items-end"><button class="btn btn-sv w-100">Create link</button></div></form>
      <div id="share-result"></div>
      <table class="table table-sm"><thead><tr><th>Permission</th><th>Expires</th><th>Used</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    $('#modal-body').dataset.fid = id; $('#modal-body').dataset.fname = name;
    modal.show();
  }

  $('#modal-body').addEventListener('submit', async e => {
    e.preventDefault();
    const id = $('#modal-body').dataset.fid, name = $('#modal-body').dataset.fname;
    try {
      if (e.target.id === 'ver-form') {
        const fd = new FormData(); fd.append('file', $('#ver-file').files[0]);
        await api(`/files/${id}/versions`, { method: 'POST', form: fd });
        toast('New version saved'); await openVersions(id, name); refreshQuota();
      } else if (e.target.id === 'share-form') {
        const body = { permission: $('#sh-perm').value, expires_minutes: +$('#sh-exp').value };
        if ($('#sh-max').value) body.max_downloads = +$('#sh-max').value;
        const d = await api(`/files/${id}/shares`, { method: 'POST', body });
        const link = `${location.origin}/share.html?token=${encodeURIComponent(d.token)}`;
        $('#share-result').innerHTML = `<div class="alert alert-success"><div class="small mb-1">Copy this link now. It is shown only once.</div>
          <div class="input-group"><input class="form-control" id="share-link" readonly value="${esc(link)}"><button type="button" class="btn btn-outline-secondary" data-m="copy">Copy</button></div></div>`;
      }
    } catch (err) { toast(err.message, 'danger'); }
  });
  $('#modal-body').addEventListener('click', async e => {
    const b = e.target.closest('[data-m]'); if (!b) return;
    const id = $('#modal-body').dataset.fid, name = $('#modal-body').dataset.fname;
    try {
      if (b.dataset.m === 'restore-version') {
        await api(`/files/${id}/versions/${b.dataset.n}/restore`, { method: 'POST' });
        toast('Version restored'); await openVersions(id, name);
      } else if (b.dataset.m === 'revoke') {
        await api(`/shares/${b.dataset.sid}`, { method: 'DELETE' }); toast('Link revoked'); await openShare(id, name);
      } else if (b.dataset.m === 'copy') {
        await navigator.clipboard.writeText($('#share-link').value); toast('Link copied');
      }
    } catch (err) { toast(err.message, 'danger'); }
  });

  /* ---------------- admin ---------------- */
  async function loadAdmin() {
    const [st, users, logs] = await Promise.all([api('/admin/stats'), api('/admin/users'), api('/admin/logs?limit=100')]);
    $('#admin-stats').innerHTML = [['Users', st.users], ['Files', st.files], ['Storage used', fmtSize(st.used_bytes)], ['Log entries', st.log_entries]]
      .map(([k, v]) => `<div class="col-6 col-md-3"><div class="card shadow-sm"><div class="card-body py-3"><div class="text-muted small">${k}</div><div class="h4 mb-0">${esc(v)}</div></div></div></div>`).join('');
    $('#admin-users').innerHTML = users.map(u => `<tr><td>${esc(u.username)}<div class="small text-muted">${esc(u.email)}</div></td><td>${u.role}</td><td>${u.file_count}</td>
      <td>${fmtSize(u.used_bytes)} / ${fmtSize(u.quota_bytes)}</td><td>${u.is_active ? '<span class="badge text-bg-success">Active</span>' : '<span class="badge text-bg-secondary">Disabled</span>'}</td>
      <td class="text-end text-nowrap"><button class="btn btn-sm btn-outline-secondary" data-adm="quota" data-uid="${u.id}">Set quota</button>
      <button class="btn btn-sm btn-outline-${u.is_active ? 'danger' : 'success'}" data-adm="toggle" data-uid="${u.id}" data-active="${u.is_active}">${u.is_active ? 'Disable' : 'Enable'}</button></td></tr>`).join('');
    $('#admin-logs').innerHTML = logs.map(r => `<tr><td>${fmtDate(r.created_at)}</td><td>${esc(r.user || '-')}</td><td>${esc(r.action)}</td><td>${esc(r.detail)}</td><td>${esc(r.ip)}</td></tr>`).join('');
  }
  $('#admin-users').addEventListener('click', async e => {
    const b = e.target.closest('[data-adm]'); if (!b) return;
    try {
      if (b.dataset.adm === 'quota') {
        const mb = prompt('New quota in MB (1 - 102400):'); if (!mb) return;
        await api(`/admin/users/${b.dataset.uid}`, { method: 'PATCH', body: { quota_mb: parseInt(mb, 10) } });
      } else {
        await api(`/admin/users/${b.dataset.uid}`, { method: 'PATCH', body: { is_active: b.dataset.active !== 'true' } });
      }
      toast('User updated'); loadAdmin();
    } catch (err) { toast(err.message, 'danger'); }
  });

  /* ---------------- start ---------------- */
  if (token) enterApp().catch(() => logout());
})();
