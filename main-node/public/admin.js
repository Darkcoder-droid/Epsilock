(() => {
  const alerts = document.getElementById('adminAlerts');
  const token = window.__ADMIN_TOKEN;
  const securityForm = document.getElementById('securitySettingsForm');
  const saveStatus = document.getElementById('settingsSaveStatus');
  const refreshBtn = document.getElementById('refreshSettingsBtn');

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(value);
  }

  function applySettingsToUi(settings) {
    if (!settings) return;
    const attackerEnabled = !!settings.attackerDemoEnabled;
    const enabled = !!settings.coverTrafficEnabled;
    setText('attackerDemoEnabledLabel', attackerEnabled ? 'ON' : 'OFF');
    setText('coverTrafficEnabledLabel', enabled ? 'ON' : 'OFF');
    setText('coverTrafficModeLabel', enabled ? 'MIXED / NOISY MODE ACTIVE' : 'CLEAN / ISOLATABLE MODE (COVER OFF)');
    
    // Sliders and Badges
    const interval = Number(settings.coverTrafficIntervalMs || 1500);
    const jitter = Number(settings.coverTrafficJitterMs || 1000);
    const ratio = Number(settings.coverTrafficRatio || 3);
    
    setText('val_interval', `${interval} ms`);
    setText('val_jitter', `${jitter} ms`);
    setText('val_ratio', `1 : ${ratio}`);

    const attackerDemoInput = document.getElementById('attackerDemoEnabled');
    const enabledInput = document.getElementById('coverTrafficEnabled');
    const intervalInput = document.getElementById('coverTrafficIntervalMs');
    const jitterInput = document.getElementById('coverTrafficJitterMs');
    const ratioInput = document.getElementById('coverTrafficRatio');
    
    if (attackerDemoInput) attackerDemoInput.value = attackerEnabled ? 'true' : 'false';
    if (enabledInput) enabledInput.value = enabled ? 'true' : 'false';
    if (intervalInput) intervalInput.value = interval;
    if (jitterInput) jitterInput.value = jitter;
    if (ratioInput) ratioInput.value = ratio;
  }

  async function fetchSecuritySettings() {
    const res = await fetch('/admin/api/security-settings', { headers: { Accept: 'application/json' } });
    if (!res.ok) return null;
    return res.json();
  }

  if (securityForm) {
    securityForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(securityForm);
      const payload = {
        attackerDemoEnabled: String(formData.get('attackerDemoEnabled')) === 'true',
        coverTrafficEnabled: String(formData.get('coverTrafficEnabled')) === 'true',
        coverTrafficIntervalMs: Number(formData.get('coverTrafficIntervalMs')),
        coverTrafficJitterMs: Number(formData.get('coverTrafficJitterMs')),
        coverTrafficRatio: Number(formData.get('coverTrafficRatio'))
      };
      const res = await fetch('/admin/api/security-settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.ok) {
        if (saveStatus) saveStatus.textContent = 'Failed to save settings';
        return;
      }
      applySettingsToUi(body.settings);
      if (saveStatus) saveStatus.textContent = `Saved at ${new Date().toLocaleTimeString()}`;
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      const settings = await fetchSecuritySettings();
      if (!settings) return;
      applySettingsToUi(settings);
      if (saveStatus) saveStatus.textContent = `Refreshed at ${new Date().toLocaleTimeString()}`;
    });
  }

  if (!token) return;

  const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${wsProtocol}//${location.host}/ws?client=admin&token=${encodeURIComponent(token)}`;
  const ws = new WebSocket(url);
  const globalStatus = document.getElementById('globalWssStatus');

  function updateGlobalStatus(online) {
    if (!globalStatus) return;
    globalStatus.className = `wss-tag ${online ? 'status-online' : 'status-offline'}`;
    globalStatus.textContent = online ? 'WSS: CONNECTED' : 'WSS: DISCONNECTED';
  }

  /* Live Clock */
  setInterval(() => {
    const el = document.getElementById('liveClock');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }, 1000);

  let audioCtx;
  let unlocked = false;
  const enableSoundBtn = document.getElementById('enableAlertSoundBtn');

  function unlockAudio() {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    if (!audioCtx) audioCtx = new Ctx();
    if (audioCtx.state === 'suspended') audioCtx.resume().catch(() => {});
    unlocked = true;
  }

  function beep() {
    if (!unlocked) return;
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    if (!audioCtx) audioCtx = new Ctx();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = 'square';
    osc.frequency.value = 880;
    gain.gain.value = 0.07;
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.15);
  }

  if (enableSoundBtn) {
    enableSoundBtn.addEventListener('click', () => {
      unlockAudio();
      if (enableSoundBtn) enableSoundBtn.textContent = 'Security Alert Sound Enabled';
    });
  } else {
    window.addEventListener('click', unlockAudio, { once: true });
  }

  function log(text) {
    if (!alerts) return;
    const line = document.createElement('p');
    line.textContent = `${new Date().toLocaleTimeString()}  ${text}`;
    alerts.prepend(line);
  }

  ws.addEventListener('open', () => updateGlobalStatus(true));
  ws.addEventListener('close', () => updateGlobalStatus(false));

  ws.addEventListener('message', (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (_e) {
      return;
    }
    if (msg.type === 'ADMIN_SECURITY_ALERT') {
      log(`[SECURITY] ${msg.reason}`);
      beep();
    }
    if (msg.type === 'INCIDENT_CREATED') {
      log(`[INCIDENT] ${msg.anomalyType || msg.type} ${msg.reason || ''}`);
      beep();
    }
    if (msg.type === 'ADMIN_NODE_EVENT') {
      log(`[NODE] ${msg.event} ${msg.nodeId || msg.client || ''}`);
      if (msg.event === 'attacker_connected' || msg.event === 'attacker_disconnected') {
        setText('attackerNodeConnectedLabel', msg.event === 'attacker_connected' ? 'YES' : 'NO');
      }
    }
    if (msg.type === 'USER_FORCE_LOGOUT_DONE') log(`[ENFORCEMENT] user force logout completed for ${msg.userId}`);
    if (msg.type === 'ROOM_FROZEN') log(`[ROOM] frozen ${msg.roomId} (${msg.reason || 'security'})`);
    if (msg.type === 'ROOM_UNFROZEN') log(`[ROOM] unfrozen ${msg.roomId}`);
    if (msg.type === 'ATTACKER_DEMO_SETTINGS_UPDATED') {
      applySettingsToUi(msg.settings || {});
      log('[DEMO] attacker demo settings updated');
    }
    if (msg.type === 'SECURITY_SETTINGS_UPDATED') {
      applySettingsToUi(msg.settings || {});
      if (saveStatus) saveStatus.textContent = `Updated live at ${new Date().toLocaleTimeString()}`;
      log('[SECURITY] security settings updated');
    }
  });

  /* Decryption Animation */
  function decryptEffect(el) {
    const original = el.textContent;
    if (!original || !/[0-9]/.test(original)) return;
    const chars = "0123456789ABCDEF!@#$%^&*";
    let iterations = 0;
    
    const interval = setInterval(() => {
      el.textContent = original.split("").map((char, index) => {
        if (index < iterations) return original[index];
        return chars[Math.floor(Math.random() * chars.length)];
      }).join("");
      
      if (iterations >= original.length) clearInterval(interval);
      iterations += 1/3;
    }, 30);
  }

  window.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.mini-stat .value').forEach(decryptEffect);
  });
})();
