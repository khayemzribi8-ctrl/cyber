/* Sentinel platform — vanilla JS, no dependencies, works offline. */
(function () {
  const csrf = () => {
    const el = document.querySelector('input[name="_csrf"]');
    return el ? el.value : '';
  };

  const Sentinel = {
    toast(msg, kind) {
      const box = document.getElementById('toasts');
      if (!box) return;
      const t = document.createElement('div');
      t.className = 'toast ' + (kind || '');
      t.textContent = msg;
      box.appendChild(t);
      setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .4s'; }, 3200);
      setTimeout(() => t.remove(), 3800);
    },

    openRun() {
      const wrap = document.getElementById('moduleChecks');
      if (wrap && !wrap.dataset.filled) {
        (window.__COLLECTORS__ || []).forEach(c => {
          const id = 'm_' + c.key;
          const dis = !c.available;
          const reason = c.reason ? ` — <span class="muted small">${c.reason}</span>` : '';
          const row = document.createElement('label');
          row.className = 'checkline';
          row.innerHTML = `<input type="checkbox" name="modules" value="${c.key}" id="${id}" ${dis ? 'disabled' : 'checked'}/>`
            + `<span>${c.label} <span class="t-id">(${c.key})</span>${dis ? reason : ''}</span>`;
          wrap.appendChild(row);
        });
        wrap.dataset.filled = '1';
      }
      document.getElementById('runModal').classList.add('open');
    },
    closeRun() { document.getElementById('runModal').classList.remove('open'); },

    async post(url, body) {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf(), 'X-Requested-With': 'fetch' },
        body: JSON.stringify(body || {})
      });
      return r.json();
    },

    async setStatus(fid, status) {
      const fd = new FormData();
      fd.append('_csrf', csrf());
      fd.append('status', status);
      const r = await fetch('/finding/' + fid + '/status', {
        method: 'POST', body: fd, headers: { 'X-Requested-With': 'fetch' }
      });
      const j = await r.json();
      if (j.ok) { this.toast('Status updated to ' + status, 'ok'); setTimeout(() => location.reload(), 500); }
      else this.toast('Could not update status', 'err');
    },

    copy(id) {
      const el = document.getElementById(id);
      if (!el) return;
      const text = el.innerText || el.textContent;
      navigator.clipboard.writeText(text).then(
        () => this.toast('Copied to clipboard', 'ok'),
        () => this.toast('Copy failed', 'err'));
    },

    async execFix(fid, channel, btn) {
      if (!confirm('This will attempt to execute an allow-listed remediation command on the target. Continue?')) return;
      if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
      const j = await this.post('/remediation/execute', { finding_id: fid, channel: channel });
      this.toast(j.message || (j.ok ? 'Executed' : 'Failed'), j.ok ? 'ok' : 'err');
      const out = document.getElementById('exec_' + fid);
      if (out) { out.style.display = 'block'; out.textContent = j.message || ''; }
      if (btn) { btn.disabled = false; btn.textContent = j.ok ? 'Re-run' : 'Retry'; }
    },

    async aiSuggest(fid, btn) {
      const out = document.getElementById('ai_' + fid);
      if (btn) { btn.disabled = true; btn.textContent = 'Asking AI…'; }
      const j = await this.post('/remediation/ai-suggest', { finding_id: fid });
      if (btn) { btn.disabled = false; btn.textContent = 'AI suggest fix'; }
      if (out) {
        out.style.display = 'block';
        if (j.ok && j.command) {
          out.innerHTML = '<div class="muted small" style="margin-bottom:6px">' + (j.backend ? j.backend + ' · ' : '') + 'AI-suggested (review before use — not executed automatically)</div>'
            + '<pre class="code" style="margin:0">' + (j.command.replace(/</g, '&lt;')) + '</pre>'
            + (j.explanation ? '<div class="small mt">' + j.explanation.replace(/</g, '&lt;') + '</div>' : '');
        } else {
          out.innerHTML = '<div class="notice warn small">' + (j.message || 'No suggestion') + '</div>';
        }
      }
      this.toast(j.message || (j.ok ? 'Suggestion ready' : 'No suggestion'), j.ok ? 'ok' : 'err');
    },

    async snsTest(btn) {
      const el = document.getElementById('snsres');
      if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
      const j = await this.post('/sns-test', {});
      if (btn) { btn.disabled = false; btn.textContent = 'Send test alert'; }
      if (el) { el.textContent = j.message || ''; el.style.color = j.ok ? 'var(--ok)' : 'var(--crit)'; }
      this.toast(j.message || (j.ok ? 'Sent' : 'Failed'), j.ok ? 'ok' : 'err');
    },

    filterTable(inputId, tableId) {
      const q = (document.getElementById(inputId).value || '').toLowerCase();
      document.querySelectorAll('#' + tableId + ' tbody tr').forEach(tr => {
        tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    }
  };

  // audit progress poller
  Sentinel.pollAudit = function (token) {
    const bar = document.getElementById('pbar');
    const stages = document.querySelectorAll('[data-stage]');
    const tick = async () => {
      try {
        const r = await fetch('/audit/status/' + token);
        const j = await r.json();
        if (bar) bar.style.width = (j.percent || 0) + '%';
        const pctEl = document.getElementById('ppct'); if (pctEl) pctEl.textContent = (j.percent || 0) + '%';
        stages.forEach(s => {
          const st = (j.stages || {})[s.dataset.stage] || 'pending';
          s.className = 'stg ' + st;
        });
        if (j.status === 'completed') {
          Sentinel.toast('Assessment complete · score ' + j.score, 'ok');
          setTimeout(() => location.href = '/', 900);
          return;
        }
        if (j.status === 'failed') { Sentinel.toast('Assessment failed: ' + (j.error || ''), 'err'); return; }
        setTimeout(tick, 700);
      } catch (e) { setTimeout(tick, 1200); }
    };
    tick();
  };

  window.Sentinel = Sentinel;
})();
