const EventEmitter = require('events');
const WebSocket = require('ws');
const { createPacket } = require('../../shared/packet');
const { PACKET_TYPES, WS_EVENTS } = require('../../shared/constants');
const { encryptText, decryptText } = require('../../shared/crypto');

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

class UserNodeClient extends EventEmitter {
  constructor({ mainWsUrl, nodeId, user, token }) {
    super();
    this.mainWsUrl = mainWsUrl;
    this.nodeId = nodeId;
    this.user = user;
    this.token = token;
    this.ws = null;
    this.connected = false;
    this.authenticated = false;
    this.joinedRoomId = null;
    this.selectedRoomId = null;
    this.coverConfig = {
      coverTrafficEnabled: String(process.env.COVER_TRAFFIC_ENABLED || 'false') === 'true',
      coverTrafficIntervalMs: Number(process.env.COVER_TRAFFIC_INTERVAL_MS || 1500),
      coverTrafficJitterMs: Number(process.env.COVER_TRAFFIC_JITTER_MS || 1000),
      coverTrafficRatio: Number(process.env.COVER_TRAFFIC_RATIO || 3)
    };
    this._coverLoopOn = false;
    this._coverTimer = null;
    this._reconnectTimer = null;
    this._stopped = false;
    this.lastError = null;
    this._joinRequest = null;
  }

  connect() {
    if (this._stopped) return;
    if (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1)) return;

    const q = `token=${encodeURIComponent(this.token)}&nodeId=${encodeURIComponent(this.nodeId)}&userId=${encodeURIComponent(this.user.userId)}`;
    const wsUrl = `${this.mainWsUrl}?${q}`;
    this.ws = new WebSocket(wsUrl, { rejectUnauthorized: false });

    this.ws.on('open', () => {
      this.connected = true;
      this.authenticated = false;
      this.joinedRoomId = null;
      this.lastError = null;
      this.emit('status', this.status());
      const hello = createPacket({
        type: PACKET_TYPES.NODE_HELLO,
        nodeId: this.nodeId,
        fromUserId: this.user.userId,
        sizeBytes: 0,
        isCover: false
      });
      this.ws.send(JSON.stringify(hello));
      this.startCoverLoop();
    });

    this.ws.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch (_e) {
        return;
      }

      if (msg.type === WS_EVENTS.COVER_TRAFFIC_CONFIG_UPDATED && msg.settings) {
        this.applyCoverConfig(msg.settings);
        this.emit('status', this.status());
        return;
      }

      if (msg.type === WS_EVENTS.NODE_AUTH_OK) {
        this.authenticated = true;
        this.lastError = null;
        this.emit('status', this.status());
        return;
      }

      if (msg.type === WS_EVENTS.NODE_AUTH_DENIED) {
        this.authenticated = false;
        this.lastError = msg.reason || 'Node auth denied';
        this.emit('status', this.status());
        return;
      }

      if (msg.type === WS_EVENTS.ROOM_JOIN_OK) {
        this.joinedRoomId = msg.roomId || this.selectedRoomId || null;
        if (this._joinRequest) {
          this._joinRequest.resolve({ ok: true, roomId: this.joinedRoomId });
          this._joinRequest = null;
        }
        this.emit('status', this.status());
        return;
      }

      if (msg.type === WS_EVENTS.ROOM_JOIN_DENIED) {
        this.joinedRoomId = null;
        const reason = msg.reason || 'Room join denied';
        if (this._joinRequest) {
          this._joinRequest.resolve({ ok: false, error: reason, roomId: msg.roomId || null });
          this._joinRequest = null;
        }
        this.emit('joinDenied', { roomId: msg.roomId || null, reason });
        this.emit('status', this.status());
        return;
      }

      if (msg.type === WS_EVENTS.SEND_DENIED) {
        this.emit('sendDenied', { reason: msg.reason || 'Send denied', roomId: msg.roomId || null });
        return;
      }

      if (msg.type === WS_EVENTS.ROOM_FROZEN) {
        if (msg.roomId && this.joinedRoomId && String(msg.roomId) === String(this.joinedRoomId)) {
          this.joinedRoomId = null;
        }
        this.emit('roomFrozen', { roomId: msg.roomId || null, reason: msg.reason || 'Room frozen by security policy' });
        this.emit('status', this.status());
        return;
      }

      if (msg.type === WS_EVENTS.FORCE_LOGOUT || msg.type === WS_EVENTS.SESSION_REVOKED) {
        this.emit('revoked', msg.reason || 'Session revoked by security policy');
        return;
      }

      if (msg.type === PACKET_TYPES.ADMIN_ALERT && msg.code === 'SESSION_REVOKED') {
        this.emit('revoked', msg.reason || 'session revoked');
      }

      if (msg.type === PACKET_TYPES.COVER_TRAFFIC || msg.isCover) {
        console.debug('Ignored cover traffic');
        return;
      }

      if (msg.type === PACKET_TYPES.REAL_MESSAGE) {
        console.debug('REAL_MESSAGE received');
        if (!this.connected || !this.authenticated || !this.joinedRoomId) return;
        if (String(msg.roomId || '') !== String(this.joinedRoomId || '')) {
          console.debug('Ignored room mismatch');
          return;
        }
        if (!msg.ciphertext || !msg.nonce || !msg.authTag) return;

        let plaintext = '[Unable to decrypt message]';
        try {
          plaintext = decryptText(msg);
        } catch (_e) {}

        this.emit('chatMessage', {
          type: WS_EVENTS.CHAT_MESSAGE_RECEIVED,
          packetId: msg.packetId,
          roomId: msg.roomId,
          fromUserId: msg.fromUserId,
          fromUsername: msg.fromUsername || 'Unknown',
          plaintext,
          createdAt: msg.createdAt || new Date().toISOString(),
          mine: String(msg.fromUserId) === String(this.user.userId)
        });
      }
    });

    this.ws.on('close', () => {
      this.connected = false;
      this.authenticated = false;
      this.joinedRoomId = null;
      this.lastError = 'WebSocket closed, retrying...';
      if (this._joinRequest) {
        this._joinRequest.resolve({ ok: false, error: 'Disconnected before room join completed' });
        this._joinRequest = null;
      }
      this.emit('status', this.status());
      this.scheduleReconnect();
    });

    this.ws.on('error', (err) => {
      this.connected = false;
      this.authenticated = false;
      this.joinedRoomId = null;
      this.lastError = err && err.message ? err.message : 'WebSocket error';
      if (this._joinRequest) {
        this._joinRequest.resolve({ ok: false, error: this.lastError });
        this._joinRequest = null;
      }
      this.emit('status', this.status());
      this.scheduleReconnect();
    });
  }

  scheduleReconnect() {
    if (this._stopped) return;
    if (this._reconnectTimer) return;
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      this.connect();
    }, 2000);
  }

  status() {
    return {
      wsConnected: this.connected,
      nodeAuthenticated: this.authenticated,
      roomJoined: !!this.joinedRoomId,
      selectedRoomId: this.selectedRoomId,
      connected: this.connected,
      authenticated: this.authenticated,
      joinedRoomId: this.joinedRoomId,
      coverEnabled: this.coverConfig.coverTrafficEnabled,
      coverTrafficIntervalMs: this.coverConfig.coverTrafficIntervalMs,
      coverTrafficJitterMs: this.coverConfig.coverTrafficJitterMs,
      coverTrafficRatio: this.coverConfig.coverTrafficRatio,
      lastError: this.lastError
    };
  }

  applyCoverConfig(nextConfig) {
    this.coverConfig = {
      coverTrafficEnabled: Boolean(nextConfig.coverTrafficEnabled),
      coverTrafficIntervalMs: Number(nextConfig.coverTrafficIntervalMs || 1500),
      coverTrafficJitterMs: Number(nextConfig.coverTrafficJitterMs || 1000),
      coverTrafficRatio: Number(nextConfig.coverTrafficRatio || 3)
    };

    if (!this.coverConfig.coverTrafficEnabled) {
      if (this._coverTimer) {
        clearTimeout(this._coverTimer);
        this._coverTimer = null;
      }
      return;
    }

    if (this._coverLoopOn) {
      this.scheduleCoverTick();
    }
  }

  async joinRoom(roomId) {
    this.selectedRoomId = roomId || null;
    this.joinedRoomId = null;
    this.emit('status', this.status());

    if (!this.ws || this.ws.readyState !== 1) {
      return { ok: false, error: 'WebSocket is not connected' };
    }
    if (!this.authenticated) {
      return { ok: false, error: 'Node authentication not complete yet' };
    }

    if (this._joinRequest) {
      this._joinRequest.resolve({ ok: false, error: 'Previous room join request was replaced' });
      this._joinRequest = null;
    }

    const reply = await new Promise((resolve) => {
      this._joinRequest = { resolve };
      this.ws.send(JSON.stringify({ type: WS_EVENTS.JOIN_ROOM, roomId: this.selectedRoomId }));
      setTimeout(() => {
        if (!this._joinRequest) return;
        this._joinRequest.resolve({ ok: false, error: 'Room join timeout' });
        this._joinRequest = null;
      }, 6000);
    });

    if (!reply.ok) {
      this.joinedRoomId = null;
    }
    this.emit('status', this.status());
    return reply;
  }

  sendRealMessage({ roomId, toUserId, text }) {
    if (!this.ws || this.ws.readyState !== 1) throw new Error('Node is not connected to main node');
    const enc = encryptText(text, {
      minBytes: Number(process.env.COVER_TRAFFIC_PACKET_MIN_BYTES || 256),
      maxBytes: Number(process.env.COVER_TRAFFIC_PACKET_MAX_BYTES || 1024)
    });
    const pkt = createPacket({
      type: PACKET_TYPES.REAL_MESSAGE,
      roomId,
      fromUserId: this.user.userId,
      toUserId,
      nodeId: this.nodeId,
      ciphertext: enc.ciphertext,
      nonce: enc.nonce,
      authTag: enc.authTag,
      sizeBytes: enc.sizeBytes,
      isCover: false
    });
    this.ws.send(JSON.stringify(pkt));
  }

  sendCoverPacket({ roomId, toUserId }) {
    if (!this.ws || this.ws.readyState !== 1) return;
    const enc = encryptText(`cover-${Date.now()}-${Math.random()}`, {
      minBytes: Number(process.env.COVER_TRAFFIC_PACKET_MIN_BYTES || 256),
      maxBytes: Number(process.env.COVER_TRAFFIC_PACKET_MAX_BYTES || 1024)
    });
    const pkt = createPacket({
      type: PACKET_TYPES.COVER_TRAFFIC,
      roomId,
      fromUserId: this.user.userId,
      toUserId,
      nodeId: this.nodeId,
      ciphertext: enc.ciphertext,
      nonce: enc.nonce,
      authTag: enc.authTag,
      sizeBytes: enc.sizeBytes,
      isCover: true
    });
    this.ws.send(JSON.stringify(pkt));
  }

  async startCoverLoop() {
    if (this._coverLoopOn) return;
    this._coverLoopOn = true;
    this.scheduleCoverTick();
  }

  scheduleCoverTick() {
    if (this._coverTimer) {
      clearTimeout(this._coverTimer);
      this._coverTimer = null;
    }
    if (!this._coverLoopOn) return;

    const interval = Number(this.coverConfig.coverTrafficIntervalMs || 1500);
    const jitter = Number(this.coverConfig.coverTrafficJitterMs || 1000);
    const delay = interval + rand(0, Math.max(jitter, 0));

    this._coverTimer = setTimeout(() => {
      if (!this._coverLoopOn) return;
      if (this.coverConfig.coverTrafficEnabled && this.connected && this.joinedRoomId) {
        const ratio = Number(this.coverConfig.coverTrafficRatio || 3);
        for (let i = 0; i < ratio; i++) {
          this.sendCoverPacket({ roomId: this.joinedRoomId, toUserId: this.user.peerUserId || null });
        }
      }
      this.scheduleCoverTick();
    }, delay);
  }

  stop() {
    this._stopped = true;
    this._coverLoopOn = false;
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this._coverTimer) {
      clearTimeout(this._coverTimer);
      this._coverTimer = null;
    }
    if (this._joinRequest) {
      this._joinRequest.resolve({ ok: false, error: 'Node stopped' });
      this._joinRequest = null;
    }
    if (this.ws && this.ws.readyState <= 1) {
      try { this.ws.close(); } catch (_e) {}
    }
  }
}

module.exports = { UserNodeClient };
