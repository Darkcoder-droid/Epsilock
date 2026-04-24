(() => {
  const boot = window.__CHAT_BOOT;
  if (!boot) return;

  const currentUser = window.EPSILOCK_USER || {};

  const statusRows = document.getElementById('statusRows');
  const statusText = document.getElementById('connectionStatus') || document.getElementById('statusText');
  const joinBtn = document.getElementById('joinRoomButton') || document.getElementById('joinBtn');
  const roomIdEl = document.getElementById('roomSelect') || document.getElementById('roomId');
  const msgEl = document.getElementById('messageInput') || document.getElementById('msg');
  const toUserEl = document.getElementById('toUserId');
  const sendBtn = document.getElementById('sendButton') || document.getElementById('sendBtn');
  const fileInput = document.getElementById('fileInput');
  const fileSendBtn = document.getElementById('fileSendBtn');
  const chatLog = document.getElementById('chatLog');

  const renderedPacketIds = new Set();

  const state = {
    wsConnected: false,
    nodeAuthenticated: false,
    roomJoined: false,
    selectedRoomId: null,
    joiningRoom: false,
    lastError: null
  };

  function applyNodeStatus(status = {}) {
    state.wsConnected = !!(status.wsConnected ?? status.connected);
    state.nodeAuthenticated = !!(status.nodeAuthenticated ?? status.authenticated);
    state.roomJoined = !!status.roomJoined;
    state.selectedRoomId = status.selectedRoomId || status.joinedRoomId || state.selectedRoomId || roomIdEl?.value || null;
    state.lastError = status.lastError || null;
  }

  function buildStatusMessage() {
    if (!state.wsConnected) return 'Connecting to secure WebSocket...';
    if (!state.nodeAuthenticated) return 'Authenticating node...';
    if (state.joiningRoom) return 'Joining room...';
    if (!state.selectedRoomId) return 'Select and join a room to start chat.';
    if (!state.roomJoined) return 'Select and join a room to start chat.';
    return state.lastError || 'Select and join a room to start chat.';
  }

  function updateChatControls() {
    const ready = state.wsConnected && state.nodeAuthenticated && state.roomJoined && !!state.selectedRoomId;

    if (msgEl) msgEl.disabled = !ready;
    if (sendBtn) sendBtn.disabled = !ready;
    if (fileInput) fileInput.disabled = !ready;
    if (fileSendBtn) fileSendBtn.disabled = !ready;

    const canJoin = state.wsConnected && state.nodeAuthenticated && !!state.selectedRoomId && !state.joiningRoom;
    if (joinBtn) joinBtn.disabled = !canJoin;

    if (statusText) {
      statusText.textContent = ready ? 'Secure room session active.' : buildStatusMessage();
    }

    if (statusRows) {
      statusRows.innerHTML = '';
      const lines = [
        `WSS connected: ${state.wsConnected ? 'yes' : 'no'}`,
        `Node authenticated: ${state.nodeAuthenticated ? 'yes' : 'no'}`,
        `Room joined: ${state.roomJoined ? `yes (${state.selectedRoomId || '-'})` : 'no'}`
      ];
      lines.forEach((line) => {
        const p = document.createElement('p');
        p.textContent = line;
        statusRows.appendChild(p);
      });
    }
  }

  function resetConnectionStateKeepRoomSelection() {
    state.wsConnected = false;
    state.nodeAuthenticated = false;
    state.roomJoined = false;
    state.joiningRoom = false;
  }

  function pushLog(text) {
    if (!chatLog) return;
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = `${new Date().toLocaleTimeString()} ${text}`;
    chatLog.appendChild(p);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  function appendChatMessage({ packetId, roomId, fromUsername, plaintext, createdAt, mine }) {
    if (!chatLog) return;
    if (!packetId || renderedPacketIds.has(packetId)) return;
    renderedPacketIds.add(packetId);

    if (!state.roomJoined) return;
    if (String(roomId || '') !== String(state.selectedRoomId || '')) {
      console.debug('Ignored room mismatch');
      return;
    }

    const row = document.createElement('div');
    row.className = mine ? 'chat-row mine' : 'chat-row theirs';

    const name = document.createElement('div');
    name.className = 'chat-name';
    name.textContent = mine ? 'You' : (fromUsername || 'Unknown');

    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    bubble.textContent = plaintext || '[Empty message]';

    const time = document.createElement('div');
    time.className = 'chat-time';
    time.textContent = new Date(createdAt || Date.now()).toLocaleTimeString();

    row.appendChild(name);
    row.appendChild(bubble);
    row.appendChild(time);
    chatLog.appendChild(row);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  state.wsConnected = false;
  state.nodeAuthenticated = false;
  state.roomJoined = false;
  state.joiningRoom = false;
  state.selectedRoomId = roomIdEl?.value || boot.status?.selectedRoomId || null;
  updateChatControls();

  const es = new EventSource('/events');
  es.onmessage = (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (_e) {
      return;
    }

    if (msg.type === 'status') {
      applyNodeStatus(msg.payload || {});
      if (!state.wsConnected) resetConnectionStateKeepRoomSelection();
      updateChatControls();
      return;
    }

    if (msg.type === 'revoked') {
      pushLog(`session revoked: ${msg.payload.reason}`);
      resetConnectionStateKeepRoomSelection();
      updateChatControls();
      setTimeout(() => { location.href = '/login'; }, 500);
      return;
    }

    if (msg.type === 'joinDenied') {
      state.joiningRoom = false;
      state.roomJoined = false;
      pushLog(`Room join denied: ${msg.payload.reason}`);
      if (statusText) statusText.textContent = `Room join denied: ${msg.payload.reason}`;
      updateChatControls();
      return;
    }

    if (msg.type === 'sendDenied') {
      pushLog(`Send denied: ${msg.payload.reason}`);
      if (statusText) statusText.textContent = `Send denied: ${msg.payload.reason}`;
      updateChatControls();
      return;
    }

    if (msg.type === 'CHAT_MESSAGE_RECEIVED') {
      const packet = msg.payload || {};
      if (packet.isCover || packet.type === 'COVER_TRAFFIC') {
        console.debug('Ignored cover traffic');
        return;
      }
      console.debug('REAL_MESSAGE received');
      appendChatMessage({
        packetId: packet.packetId,
        roomId: packet.roomId,
        fromUsername: packet.fromUsername,
        plaintext: packet.plaintext,
        createdAt: packet.createdAt,
        mine: packet.mine || String(packet.fromUserId || '') === String(currentUser.userId || '')
      });
      return;
    }
  };

  es.onerror = () => {
    resetConnectionStateKeepRoomSelection();
    state.lastError = 'Disconnected. Reconnect required.';
    updateChatControls();
  };

  roomIdEl?.addEventListener('change', () => {
    state.selectedRoomId = roomIdEl.value || null;
    state.roomJoined = false;
    state.joiningRoom = false;
    updateChatControls();
  });

  joinBtn?.addEventListener('click', async () => {
    if (!state.selectedRoomId) return;
    state.joiningRoom = true;
    state.roomJoined = false;
    updateChatControls();

    const res = await fetch('/api/join-room', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ roomId: state.selectedRoomId })
    });
    const data = await res.json().catch(() => ({}));

    state.joiningRoom = false;
    if (!res.ok || !data.ok) {
      state.roomJoined = false;
      const reason = data.error || `Room join failed (HTTP ${res.status})`;
      if (statusText) statusText.textContent = `Room join denied: ${reason}`;
      pushLog(`Room join denied: ${reason}`);
      updateChatControls();
      return;
    }

    applyNodeStatus(data.status || {});
    state.roomJoined = true;
    updateChatControls();
    pushLog(`joined room ${state.selectedRoomId}`);
  });

  sendBtn?.addEventListener('click', async () => {
    const text = msgEl.value.trim();
    if (!text || !state.selectedRoomId) return;

    const res = await fetch('/api/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ roomId: state.selectedRoomId, toUserId: toUserEl?.value.trim() || null, text })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      pushLog(data.error || 'send failed');
      if (statusText) statusText.textContent = data.error || 'Send denied';
      return;
    }
    msgEl.value = '';
  });

  fileSendBtn?.addEventListener('click', () => {
    pushLog('Temporary file send hook is not enabled in this view yet.');
  });
})();
