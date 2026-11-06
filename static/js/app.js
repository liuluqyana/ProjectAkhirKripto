/* Secure Exam Distribution Vault - JavaScript sisi klien (tanpa framework). */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  const page = document.body.dataset.page || '';

  // ---------- Util ----------
  async function api(url, { method = 'GET', json, form } = {}) {
    const opts = { method, credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf() } };
    if (json !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(json);
    } else if (form) {
      opts.body = form;
    }
    const res = await fetch(url, opts);
    const type = res.headers.get('content-type') || '';
    if (!res.ok) {
      let msg = 'Kesalahan ' + res.status;
      if (type.includes('json')) {
        try { msg = (await res.json()).error || msg; } catch (e) { /* abaikan */ }
      }
      throw new Error(msg);
    }
    if (type.includes('json')) return { data: await res.json(), res };
    return { blob: await res.blob(), res };
  }

  function saveBlob(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  const filenameOf = (res, fallback) => {
    const h = res.headers.get('X-Filename');
    return h ? decodeURIComponent(h) : fallback;
  };

  function show(el, text) { el.textContent = text; el.classList.remove('hidden'); }
  function hide(...els) { els.forEach((e) => e && e.classList.add('hidden')); }

  async function withBusy(btn, fn) {
    btn.disabled = true;
    try { return await fn(); } finally { btn.disabled = false; }
  }

  function wireForm(form, { errorEl, okEl, run }) {
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      hide(errorEl, okEl);
      const btn = form.querySelector('button[type=submit]');
      try { await withBusy(btn, () => run(form)); }
      catch (err) { show(errorEl, err.message); }
    });
  }

  // ---------- Waktu lokal ----------
  document.querySelectorAll('time[data-utc]').forEach((t) => {
    const d = new Date(t.dataset.utc);
    if (!isNaN(d)) t.textContent = d.toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' });
  });

  // ---------- Helper base64url / hex ----------
  const b64uToBuf = (s) => {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const bufToB64u = (buf) => {
    let s = '';
    new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const hexToBytes = (hex) => {
    if (!/^([0-9a-f]{2})+$/i.test(hex)) throw new Error('Rahasia dongle bukan hex yang valid.');
    return Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
  };
  const bytesToHex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');

  // ---------- WebAuthn ----------
  const webauthnSupported = () => !!(window.PublicKeyCredential && navigator.credentials);

  async function webauthnRegister() {
    const { data: opts } = await api('/api/webauthn/register/options', { method: 'POST', json: {} });
    opts.challenge = b64uToBuf(opts.challenge);
    opts.user.id = b64uToBuf(opts.user.id);
    (opts.excludeCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    const cred = await navigator.credentials.create({ publicKey: opts });
    const payload = {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
    if (cred.response.getTransports) payload.response.transports = cred.response.getTransports();
    await api('/api/webauthn/register/verify', { method: 'POST', json: payload });
  }

  async function webauthnLogin() {
    const { data: opts } = await api('/api/login/webauthn/options', { method: 'POST', json: {} });
    opts.challenge = b64uToBuf(opts.challenge);
    (opts.allowCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    const cred = await navigator.credentials.get({ publicKey: opts });
    const payload = {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        signature: bufToB64u(cred.response.signature),
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
    if (cred.response.userHandle) payload.response.userHandle = bufToB64u(cred.response.userHandle);
    const { data } = await api('/api/login/webauthn/verify', { method: 'POST', json: payload });
    window.location.href = data.redirect;
  }

  // ---------- Dongle demo (challenge-response HMAC-SHA256) ----------
  async function dongleLogin(file) {
    if (!window.crypto || !crypto.subtle) {
      throw new Error('WebCrypto tidak tersedia. Buka lewat http://localhost atau HTTPS.');
    }
    if (!file) throw new Error('Pilih berkas token dongle terlebih dahulu.');
    let token;
    try { token = JSON.parse(await file.text()); } catch (e) { throw new Error('Berkas token bukan JSON yang valid.'); }
    if (token.type !== 'KGP-DEMO-DONGLE' || !token.secret || !token.username) {
      throw new Error('Berkas bukan token dongle demo yang valid.');
    }
    const { data: ch } = await api('/api/login/dongle/challenge', { method: 'POST', json: {} });
    if (token.username !== ch.username) throw new Error('Token ini milik akun lain (' + token.username + ').');
    const key = await crypto.subtle.importKey('raw', hexToBytes(token.secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const msg = new TextEncoder().encode('KGP-DONGLE|' + ch.username + '|' + ch.challenge);
    const sig = await crypto.subtle.sign('HMAC', key, msg);
    const { data } = await api('/api/login/dongle/verify', { method: 'POST', json: { response: bytesToHex(sig) } });
    window.location.href = data.redirect;
  }

  // ---------- Login: halaman username + password saja ----------
  function initLogin() {
    const form = $('#form-password');
    wireForm(form, { errorEl: $('#login-error'), run: async () => {
      const { data } = await api('/api/login/password', { method: 'POST', json: {
        username: $('#username').value, password: $('#password').value,
      }});
      window.location.assign(data.redirect);
    }});
  }

  // ---------- Kamera eksternal (browser getUserMedia) ----------
  async function openCamera() {
    if (!navigator.mediaDevices?.getUserMedia) throw new Error('Webcam membutuhkan localhost/HTTPS dan izin kamera.');
    const stream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480, facingMode: 'user' }, audio: false });
    const video = $('#face-video');
    video.srcObject = stream;
    await video.play();
    if (!video.videoWidth) await new Promise((r) => { video.onloadedmetadata = r; });
    window.addEventListener('pagehide', () => stream.getTracks().forEach((track) => track.stop()), { once: true });
    return video;
  }
  function captureFace(video) {
    if (!video || !video.videoWidth) throw new Error('Webcam belum siap.');
    const canvas = document.createElement('canvas'); canvas.width = 640; canvas.height = 480;
    canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL('image/jpeg', 0.82);
  }
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  async function initFace(mode) {
    const err = $('#factor-error'); const ok = $('#factor-ok');
    const btn = mode === 'enroll' ? $('#btn-face-enroll') : $('#btn-face-verify');
    let video;
    try { video = await openCamera(); }
    catch (e) { show(err, e.message); btn.disabled = true; return; }
    btn.addEventListener('click', async () => {
      hide(err, ok);
      try {
        await withBusy(btn, async () => {
          if (mode === 'enroll') {
            const password = $('#new-password').value;
            if (password.length < 10 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) throw new Error('Password baru harus minimal 10 karakter, dengan huruf besar, kecil, dan angka.');
            const frames = [];
            for (let i = 0; i < 5; i++) {
              show(ok, 'Mengambil sampel wajah ' + (i + 1) + '/5. Gerakkan kepala sedikit.');
              frames.push(captureFace(video)); await sleep(450);
            }
            const { data } = await api('/api/face/enroll', { method: 'POST', json: { frames, new_password: password } });
            window.location.assign(data.redirect);
          } else {
            const { data } = await api('/api/face/verify', { method: 'POST', json: { frame: captureFace(video) } });
            window.location.assign(data.redirect);
          }
        });
      } catch (e) { hide(ok); show(err, e.message); }
    });
  }

  function initDongle() {
    const err = $('#factor-error');
    const demo = $('#btn-dongle');
    if (demo) demo.addEventListener('click', async () => {
      hide(err);
      try { await withBusy(demo, () => dongleLogin($('#dongle-file').files[0])); }
      catch (e) { show(err, e.message); }
    });
    const securityKey = $('#btn-webauthn');
    if (securityKey) securityKey.addEventListener('click', async () => {
      hide(err);
      try { await withBusy(securityKey, webauthnLogin); }
      catch (e) { show(err, e.message); }
    });
  }

  // ---------- Halaman: dashboard ----------
  function initDashboard() {
    const btn = $('#btn-register-webauthn');
    if (!btn) return;
    const status = $('#webauthn-status');
    btn.addEventListener('click', async () => {
      status.className = 'alert hidden';
      try {
        if (!webauthnSupported()) throw new Error('Browser ini tidak mendukung WebAuthn.');
        await withBusy(btn, webauthnRegister);
        status.className = 'alert alert-ok';
        status.textContent = 'Perangkat berhasil didaftarkan. Muat ulang halaman untuk melihat jumlah terbaru.';
      } catch (err) {
        status.className = 'alert alert-error';
        status.textContent = err.message;
      }
    });
  }

  // ---------- Halaman: super enkripsi teks ----------
  function initText() {
    const copyBtn = $('#copy-cipher');
    wireForm($('#form-text-encrypt'), {
      errorEl: $('#enc-error'), okEl: $('#enc-result'),
      run: async () => {
        const { data } = await api('/api/text/encrypt', { method: 'POST', json: {
          text: $('#enc-text').value, vigenere_key: $('#enc-vkey').value,
          passphrase: $('#enc-pass').value, title: $('#enc-title').value } });
        $('#enc-layer1').value = data.layer1;
        $('#enc-cipher').value = data.ciphertext;
        $('#enc-saved').textContent = data.saved_id
          ? 'Tersimpan di database (id ' + data.saved_id + '). Muat ulang halaman untuk melihat daftar.' : '';
        $('#enc-result').classList.remove('hidden');
      },
    });
    wireForm($('#form-text-decrypt'), {
      errorEl: $('#dec-error'), okEl: $('#dec-result'),
      run: async () => {
        const { data } = await api('/api/text/decrypt', { method: 'POST', json: {
          ciphertext: $('#dec-cipher').value, vigenere_key: $('#dec-vkey').value,
          passphrase: $('#dec-pass').value } });
        $('#dec-layer1').value = data.layer1;
        $('#dec-plain').value = data.plaintext;
        $('#dec-result').classList.remove('hidden');
      },
    });
    copyBtn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText($('#enc-cipher').value); copyBtn.textContent = 'Tersalin'; }
      catch (e) { $('#enc-cipher').select(); }
    });
    document.querySelectorAll('.js-load-key').forEach((b) => b.addEventListener('click', async () => {
      hide($('#dec-error'));
      try {
        const { data } = await api('/api/text/keys/' + encodeURIComponent(b.dataset.keyId));
        $('#dec-cipher').value = data.ciphertext;
        $('#dec-cipher').scrollIntoView({ behavior: 'smooth', block: 'center' });
      } catch (err) { show($('#dec-error'), err.message); }
    }));
  }

  // ---------- Halaman: file ----------
  function initFiles() {
    const release = $('#form-release');
    if (release) {
      wireForm(release, {
        errorEl: $('#rel-error'), okEl: $('#rel-result'),
        run: async (form) => {
          const fd = new FormData();
          fd.append('exam_name', $('#rel-name').value);
          fd.append('exam_file', $('#rel-file').files[0]);
          const cover = $('#rel-cover').files[0];
          if (cover) fd.append('cover', cover);
          const when = $('#rel-when').value;
          if (when) fd.append('available_from', new Date(when).toISOString());
          const { data } = await api('/api/files/release', { method: 'POST', form: fd });
          const kv = $('#rel-kv');
          kv.textContent = '';
          [['ID paket', data.package_id], ['Blok ledger', '#' + data.block_index],
           ['Hash blok', data.block_hash], ['SHA-256 .kgp', data.encrypted_sha256],
           ['SHA-256 stego', data.stego_sha256]].forEach(([k, v]) => {
            const dt = document.createElement('dt'); dt.textContent = k;
            const dd = document.createElement('dd'); dd.textContent = v;
            kv.append(dt, dd);
          });
          $('#rel-dl-enc').href = '/packages/' + data.package_id + '/download/enc';
          $('#rel-dl-stego').href = '/packages/' + data.package_id + '/download/stego';
          $('#rel-result').classList.remove('hidden');
          form.reset();
        },
      });
    }

    const enc = $('#form-encrypt');
    if (enc) {
      wireForm(enc, {
        errorEl: $('#enc-error'), okEl: $('#enc-ok'),
        run: async () => {
          const fd = new FormData();
          fd.append('file', $('#enc-file').files[0]);
          fd.append('passphrase', $('#enc-pass').value);
          const { blob, res } = await api('/api/files/encrypt', { method: 'POST', form: fd });
          const name = filenameOf(res, 'naskah.kgp');
          saveBlob(blob, name);
          show($('#enc-ok'), 'Berkas terenkripsi diunduh: ' + name);
        },
      });
    }

    wireForm($('#form-decrypt'), {
      errorEl: $('#dec-error'), okEl: $('#dec-ok'),
      run: async () => {
        const fd = new FormData();
        fd.append('kgp_file', $('#dec-kgp').files[0]);
        const stego = $('#dec-stego').files[0];
        if (stego) fd.append('stego_image', stego);
        fd.append('passphrase', $('#dec-pass').value);
        const { blob, res } = await api('/api/files/decrypt', { method: 'POST', form: fd });
        const name = filenameOf(res, 'naskah_soal');
        saveBlob(blob, name);
        show($('#dec-ok'), 'Naskah soal berhasil didekripsi: ' + name);
      },
    });
  }

  // ---------- Halaman: steganografi ----------
  function initStego() {
    const embed = $('#form-embed');
    if (embed) {
      wireForm(embed, {
        errorEl: $('#emb-error'), okEl: $('#emb-result'),
        run: async () => {
          const fd = new FormData();
          fd.append('message', $('#emb-msg').value);
          const cover = $('#emb-cover').files[0];
          if (cover) fd.append('cover', cover);
          const { blob, res } = await api('/api/stego/embed', { method: 'POST', form: fd });
          $('#emb-preview').src = URL.createObjectURL(blob);
          $('#emb-result').classList.remove('hidden');
          saveBlob(blob, filenameOf(res, 'stego_logo_upn.png'));
        },
      });
    }
    wireForm($('#form-extract'), {
      errorEl: $('#ext-error'), okEl: $('#ext-result'),
      run: async () => {
        const fd = new FormData();
        fd.append('image', $('#ext-image').files[0]);
        const { data } = await api('/api/stego/extract', { method: 'POST', form: fd });
        $('#ext-msg').value = data.message;
        $('#ext-len').textContent = data.length;
        $('#ext-result').classList.remove('hidden');
      },
    });
  }

  // ---------- Halaman: blockchain ----------
  function initChain() {
    const btn = $('#btn-verify');
    btn.addEventListener('click', async () => {
      const status = $('#verify-status');
      const list = $('#verify-errors');
      try {
        await withBusy(btn, async () => {
          const { data } = await api('/api/blockchain/verify');
          status.className = 'alert ' + (data.valid ? 'alert-ok' : 'alert-error');
          status.textContent = data.valid
            ? 'Rantai valid: ' + data.length + ' blok terverifikasi dan berkas paket cocok dengan ledger.'
            : 'Integritas bermasalah.';
          list.textContent = '';
          data.errors.forEach((e) => { const li = document.createElement('li'); li.textContent = e; list.appendChild(li); });
        });
      } catch (err) {
        status.className = 'alert alert-error';
        status.textContent = err.message;
      }
    });
  }

  // ---------- Auto-Lock / Heartbeat Pemantau Sesi (Hanya aktif di Dashboard) ----------
function initAutoLock() {
    setInterval(async () => {
      const currentPage = document.body.dataset.page;
      // Jangan jalankan saat masih di halaman login atau verifikasi
      if (['login', 'face-verify', 'face-enroll', 'dongle'].includes(currentPage)) {
        return; 
      }

      try {
        const res = await fetch('/api/auth/heartbeat', {
          method: 'GET',
          credentials: 'same-origin',
          headers: { 'X-CSRF-Token': csrf() }
        });

        // Jika server menolak karena flash disk dicabut / sesi terputus
        if (!res.ok) {
          alert("Peringatan: Flash disk dongle dicabut! Sistem dikunci demi keamanan.");
          window.location.href = '/login';
        }
      } catch (err) {
        console.error('Koneksi terputus:', err);
      }
    }, 3000); // Cek setiap 3 detik agar responsif saat dicabut
  }
  initAutoLock();

  const inits = { login: initLogin, 'face-verify': () => initFace('verify'), 'face-enroll': () => initFace('enroll'), dongle: initDongle, dashboard: initDashboard, text: initText, files: initFiles, stego: initStego, chain: initChain };
  if (inits[page]) inits[page]();
})();