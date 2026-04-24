(() => {
  const byId = (id) => document.getElementById(id);

  function setText(id, value) {
    const el = byId(id);
    if (el) el.textContent = String(value);
  }

  function renderPackets(packets) {
    const tbody = byId('packetRows');
    if (!tbody) return;
    tbody.innerHTML = '';

    packets.slice(0, 180).forEach((p) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${new Date(p.time).toLocaleTimeString()}</td>
        <td class="mono">${p.packetId}</td>
        <td>${p.type}</td>
        <td>${p.roomId}</td>
        <td>${p.fromUserId}</td>
        <td>${p.toUserId}</td>
        <td>${p.sizeBytes}</td>
        <td>${p.isCover ? 'yes' : 'no'}</td>
        <td>${p.decryptStatus}</td>
        <td class="small">${p.decryptedPreview || '-'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function apply(state) {
    if (!state) return;
    setText('connStatus', state.connected ? 'CONNECTED' : 'DISCONNECTED');
    setText('authStatus', state.authenticated ? 'OK' : 'PENDING');
    setText('tlsStatus', state.tlsWss || 'WSS');
    setText('leakedKeyMode', state.demoLeakedKeyMode ? 'ON' : 'OFF');
    setText('attackerDemoEnabled', state.settings?.attackerDemoEnabled ? 'ON' : 'OFF');
    setText('coverStatus', state.settings?.coverTrafficEnabled ? 'ON' : 'OFF');
    setText('coverInterval', Number(state.settings?.coverTrafficIntervalMs || 1500));
    setText('coverJitter', Number(state.settings?.coverTrafficJitterMs || 1000));
    setText('coverRatio', Number(state.settings?.coverTrafficRatio || 3));
    setText('confidence', state.confidence || '-');
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
