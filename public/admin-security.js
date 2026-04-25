(() => {
  if (!document.body.classList.contains('admin-page')) return;
  const box = document.getElementById('adminAlerts');
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws`);
  let audioCtx = null;
  let audioUnlocked = false;

  function push(text) {
    if (!box) return;
    const p = document.createElement('p');
    p.textContent = text;
    box.prepend(p);
  }

  function ensureAudioContext() {
    if (audioCtx) return audioCtx;
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return null;
    audioCtx = new Ctx();
    return audioCtx;
  }

  function unlockAudio() {
    const ctx = ensureAudioContext();
    if (!ctx) return;
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    audioUnlocked = true;
  }

  function beep({ frequency = 880, durationMs = 180, gain = 0.08 } = {}) {
    const ctx = ensureAudioContext();
    if (!ctx || !audioUnlocked) return;
    if (ctx.state === 'suspended') return;

    const osc = ctx.createOscillator();
    const gainNode = ctx.createGain();
    osc.type = 'square';
    osc.frequency.setValueAtTime(frequency, ctx.currentTime);
    gainNode.gain.setValueAtTime(gain, ctx.currentTime);
    osc.connect(gainNode);
    gainNode.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + durationMs / 1000);
  }

  function playSecurityAlarm() {
    beep({ frequency: 920, durationMs: 140, gain: 0.09 });
    setTimeout(() => beep({ frequency: 720, durationMs: 160, gain: 0.08 }), 180);
  }

  window.addEventListener('click', unlockAudio, { once: true });
  window.addEventListener('keydown', unlockAudio, { once: true });

  ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'ADMIN_SECURITY_ALERT') {
      push(`[ALERT] ${msg.reason}`);
      playSecurityAlarm();
    }
    if (msg.type === 'INCIDENT_CREATED') {
      push(`Incident created: ${msg.incidentId}`);
      playSecurityAlarm();
    }
    if (msg.type === 'INCIDENT_RESOLVED') push(`Incident resolved: ${msg.incidentId}`);
    if (msg.type === 'RECOVERY_STARTED') push(`Recovery started: ${msg.recoveryId}`);
    if (msg.type === 'RECOVERY_COMPLETED') push(`Recovery completed: ${msg.newRoomId}`);
    if (msg.type === 'RECOVERY_FAILED') push(`Recovery failed: ${msg.reason}`);
  });
})();
