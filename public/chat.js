(() => {
  if (!window.EPSI_CHAT) return;

  const { roomId: preselectedRoomId, roomFrozen } = window.EPSI_CHAT;
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';

  const chatThread = document.getElementById('chatThread');
  const chatInput = document.getElementById('chatInput');
  const sendBtn = document.getElementById('sendBtn');
  const roomSelect = document.getElementById('roomSelect');
  const joinRoomBtn = document.getElementById('joinRoomBtn');
  const sessionStatusText = document.getElementById('sessionStatusText');

  let ws = null;
  let socketReady = false;
  let roomJoined = false;
  let joinRequested = false;
  let frozen = !!roomFrozen;
  let currentRoomId = preselectedRoomId || (roomSelect ? roomSelect.value : '');

  function setStatus(text, cls) {
    if (sessionStatusText) {
      sessionStatusText.className = `mono-text ${cls || 'text-gray'}`;
      sessionStatusText.textContent = text;
    }
    const wssIndicator = document.getElementById('wssStatusChat');
    if (wssIndicator) {
      const isOnline = text.includes('ready') || text.includes('active') || text.includes('Joining');
      wssIndicator.className = `status-indicator ${isOnline ? 'status-online' : 'status-offline'}`;
      wssIndicator.textContent = isOnline ? 'WSS: CONNECTED' : 'WSS: DISCONNECTED';
    }
  }

  function append(text, cls = 'msg-received') {
    if (!chatThread) return;
    const div = document.createElement('div');
    div.className = `msg ${cls}`;
    div.innerHTML = `
      <div class="msg-meta"><span>System</span><span>${new Date().toLocaleTimeString()}</span></div>
      <div class="msg-body">${text}</div>
    `;
    chatThread.appendChild(div);
    chatThread.scrollTop = chatThread.scrollHeight;
  }

  function setInputState(enabled) {
    const canUse = enabled && roomJoined && !frozen;
    if (chatInput) chatInput.disabled = !canUse;
    if (sendBtn) sendBtn.disabled = !canUse;
  }

  function ensureSocket() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;

    ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws`);
    window.ws = ws;
    socketReady = false;
    setStatus('Connecting secure channel...', 'text-amber');

    ws.addEventListener('open', () => {
      socketReady = true;
      setStatus('Secure channel ready. Join room to start session.', 'text-green');
      append('Secure connection established.');
      const wssIndicator = document.getElementById('wssStatusChat');
      if (wssIndicator) {
        wssIndicator.className = 'status-indicator status-online';
        wssIndicator.textContent = 'WSS: CONNECTED';
      }
      if (joinRequested && currentRoomId) {
        ws.send(JSON.stringify({ type: 'JOIN_ROOM', roomId: currentRoomId }));
      }
    });

    ws.addEventListener('close', () => {
      socketReady = false;
      roomJoined = false;
      setInputState(false);
      setStatus('Disconnected. Join again to restart session.', 'text-red');
      const wssIndicator = document.getElementById('wssStatusChat');
      if (wssIndicator) {
        wssIndicator.className = 'status-indicator status-offline';
        wssIndicator.textContent = 'WSS: DISCONNECTED';
      }
    });

    ws.addEventListener('message', (event) => {
      const msg = JSON.parse(event.data);

      if (msg.type === 'JOIN_ROOM' && msg.ok) {
        roomJoined = true;
        joinRequested = false;
        frozen = false;
        setInputState(true);
        setStatus(`Session active in ${msg.roomId}`, 'text-green');
        append(`Joined room ${msg.roomId}.`);
        return;
      }

      if (msg.type === 'CHAT_MESSAGE') {
        const mine = window.currentUserContext && msg.fromUsername === window.currentUserContext.name;
        const div = document.createElement('div');
        div.className = `msg ${mine ? 'msg-sent' : 'msg-received'}`;
        div.innerHTML = `
          <div class="msg-meta"><span>${msg.fromUsername}</span><span>${new Date(msg.at).toLocaleTimeString()}</span></div>
          <div class="msg-body">${msg.text}</div>
        `;
        chatThread.appendChild(div);
        chatThread.scrollTop = chatThread.scrollHeight;
        return;
      }

      if (msg.type === 'TOKEN_REVOKED') {
        append(msg.reason || 'Token revoked. Redirecting to login.');
        setTimeout(() => { window.location.href = '/login'; }, 900);
        return;
      }

      if (msg.type === 'SECURITY_ALERT' || msg.type === 'SESSION_FROZEN') {
        frozen = true;
        roomJoined = false;
        setInputState(false);
        setStatus('Session frozen by security policy', 'text-red');
        append(msg.reason || 'Suspicious activity was detected. This room has been frozen for safety.');
        return;
      }

      if (msg.type === 'RECOVERY_REQUIRED') {
        frozen = true;
        roomJoined = false;
        setInputState(false);
        setStatus('Recovery required', 'text-red');
        append('Recovery required. Open secure recovery flow.');
        if (msg.recoveryId) {
          const a = document.createElement('a');
          a.href = `/recovery/${msg.recoveryId}`;
          a.textContent = 'Start secure recovery';
          a.style.display = 'block';
          a.style.marginTop = '8px';
          chatThread.appendChild(a);
        }
        return;
      }

      if (msg.type === 'ERROR') {
        append(`Error: ${msg.message}`);
      }
    });
  }

  setInputState(false);
  if (!currentRoomId) {
    setStatus('Select a room and click Join Room to start session.', 'text-amber');
    append('Select a room first, then join to start secure session.');
  } else {
    setStatus('Click Join Room to start session.', 'text-amber');
  }

  if (sendBtn && chatInput) {
    sendBtn.addEventListener('click', () => {
      if (!ws || ws.readyState !== WebSocket.OPEN || !roomJoined || frozen) return;
      const text = chatInput.value.trim();
      if (!text || !currentRoomId) return;
      ws.send(JSON.stringify({ type: 'CHAT_MESSAGE', roomId: currentRoomId, text: text.slice(0, 2000) }));
      chatInput.value = '';
    });

    chatInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') sendBtn.click();
    });
  }

  if (roomSelect) {
    roomSelect.addEventListener('change', () => {
      currentRoomId = roomSelect.value;
      frozen = false;
      roomJoined = false;
      setInputState(false);
      if (!currentRoomId) {
        setStatus('Select a room and click Join Room to start session.', 'text-amber');
        return;
      }

      setStatus(`Room selected: ${currentRoomId}. Click Join Room.`, 'text-amber');
    });
  }

  if (joinRoomBtn) {
    joinRoomBtn.addEventListener('click', () => {
      if (!currentRoomId) {
        append('Select a room before joining.');
        setStatus('Room required before join', 'text-red');
        return;
      }

      joinRequested = true;
      if (!ws || ws.readyState === WebSocket.CLOSED) {
        ensureSocket();
        return;
      }

      if (ws.readyState === WebSocket.CONNECTING) {
        setStatus('Connecting secure channel...', 'text-amber');
        return;
      }

      ws.send(JSON.stringify({ type: 'JOIN_ROOM', roomId: currentRoomId }));
      setStatus(`Joining ${currentRoomId}...`, 'text-amber');
    });
  }

  window.addEventListener('beforeunload', () => {
    try {
      if (ws && ws.readyState === WebSocket.OPEN && currentRoomId && roomJoined) {
        ws.send(JSON.stringify({ type: 'LEAVE_ROOM', roomId: currentRoomId }));
      }
    } catch (_err) {}
  });
})();
