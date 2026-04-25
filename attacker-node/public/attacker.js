(() => {
  const byId = (id) => document.getElementById(id);

  function setText(id, value) {
    const el = byId(id);
    if (el) el.textContent = String(value);
  }

  function setBadge(id, cond, textTrue, textFalse, classTrue, classFalse) {
    const el = byId(id);
    if (!el) return;
    el.textContent = cond ? textTrue : textFalse;
    el.className = `badge ${cond ? classTrue : classFalse}`;
  }

  function setConfidenceBadge(id, val) {
    const el = byId(id);
    if (!el) return;
    el.textContent = val || '-';
    el.className = `badge ${val === 'LOW' ? 'bg-red' : 'bg-green'}`;
  }

  function renderPackets(packets) {
    const tbody = byId('packetRows');
    if (!tbody) return;
    tbody.innerHTML = '';

    packets.slice(0, 180).forEach((p) => {
      const tr = document.createElement('tr');
      tr.className = p.isCover ? 'row-cover' : 'row-real';
      tr.innerHTML = `
        <td>${new Date(p.time).toLocaleTimeString()}</td>
        <td class="mono">${p.packetId}</td>
        <td>${p.type}</td>
        <td>${p.roomId}</td>
        <td>${p.fromUserId}</td>
        <td>${p.toUserId}</td>
        <td>${p.sizeBytes}</td>
        <td>${p.isCover ? 'YES' : 'NO'}</td>
        <td>${p.decryptStatus}</td>
        <td class="small">${p.decryptedPreview || '-'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function apply(state) {
    if (!state) return;
    setBadge('connStatus', state.connected, 'CONNECTED', 'DISCONNECTED', 'bg-green', 'bg-red');
    setBadge('authStatus', state.authenticated, 'OK', 'PENDING', 'bg-green', 'bg-amber');
    setText('tlsStatus', state.tlsWss || 'WSS');
    
    /* Update Tactical WSS Indicator */
    const wssIndicator = byId('wssStatusAttacker');
    if (wssIndicator) {
      wssIndicator.className = `wss-tag ${state.connected ? 'status-online' : 'status-offline'}`;
      wssIndicator.textContent = state.connected ? 'SRV: CONNECTED' : 'SRV: DISCONNECTED';
    }

    setBadge('leakedKeyMode', state.demoLeakedKeyMode, 'ON', 'OFF', 'bg-amber', 'bg-green');
    setBadge('attackerDemoEnabled', state.settings?.attackerDemoEnabled, 'ON', 'OFF', 'bg-red', 'bg-green');
    setBadge('coverStatus', state.settings?.coverTrafficEnabled, 'ON', 'OFF', 'bg-green', 'bg-red');
    
    setText('coverInterval', Number(state.settings?.coverTrafficIntervalMs || 1500));
    setText('coverJitter', Number(state.settings?.coverTrafficJitterMs || 1000));
    setText('coverRatio', Number(state.settings?.coverTrafficRatio || 3));
    setConfidenceBadge('confidence', state.confidence);
    setText('totalPackets', Number(state.stats?.totalPackets || 0));
    setText('realPackets', Number(state.stats?.realPackets || 0));
    setText('coverPackets', Number(state.stats?.coverPackets || 0));
    setText('decryptSuccess', Number(state.stats?.decryptionSuccess || 0));

    const note = byId('confidenceNote');
    if (note) {
      note.textContent = state.settings?.coverTrafficEnabled
        ? 'Cover traffic adds noise and reduces timing-analysis confidence. It does not make the system unhackable.'
        : 'Without cover traffic, timing and real-message patterns are easier to isolate.';
    }

    renderPackets(state.packets || []);
  }

  /* Live Clock */
  setInterval(() => {
    const el = byId('liveClock');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }, 1000);

  const es = new EventSource('/events');
  es.onmessage = (ev) => {
    try {
      const state = JSON.parse(ev.data);
      apply(state);
    } catch (_e) {}
  };

  const clearBtn = byId('clearBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      await fetch('/api/clear', { method: 'POST' });
    });
  }
})();
