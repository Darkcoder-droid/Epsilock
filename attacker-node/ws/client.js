const EventEmitter = require("events");
const WebSocket = require("ws");
const { PACKET_TYPES, WS_EVENTS } = require("../../shared/constants");
const { decryptText } = require("../../shared/crypto");

class AttackerDemoClient extends EventEmitter {
  constructor({ mainWsUrl, attackerToken, nodeId }) {
    super();
    this.mainWsUrl = mainWsUrl;
    this.attackerToken = attackerToken;
    this.nodeId = nodeId || "ATTACKER-NODE-1";
    this.ws = null;
    this.connected = false;
    this.authenticated = false;
    this.lastError = null;
    this.settings = {
      attackerDemoEnabled:
        String(process.env.ATTACKER_DEMO_ENABLED || "true") === "true",
      coverTrafficEnabled:
        String(process.env.COVER_TRAFFIC_ENABLED || "false") === "true",
      coverTrafficIntervalMs: Number(
        process.env.COVER_TRAFFIC_INTERVAL_MS || 1500,
      ),
      coverTrafficJitterMs: Number(process.env.COVER_TRAFFIC_JITTER_MS || 1000),
      coverTrafficRatio: Number(process.env.COVER_TRAFFIC_RATIO || 3),
    };
    this.stats = {
      totalPackets: 0,
      realPackets: 0,
      coverPackets: 0,
      decryptionSuccess: 0,
      decryptionFailed: 0,
    };
    this.recentPackets = [];
    this._reconnectTimer = null;
  }

  connect() {
    if (!this.attackerToken) {
      this.lastError = "ATTACKER_DEMO_TOKEN is missing";
      this.emit("update", this.snapshot());
      return;
    }

    const sep = this.mainWsUrl.includes("?") ? "&" : "?";
    const wsUrl = `${this.mainWsUrl}${sep}client=attacker&token=${encodeURIComponent(this.attackerToken)}`;
    this.ws = new WebSocket(wsUrl, { rejectUnauthorized: false });

    this.ws.on("open", () => {
      this.connected = true;
      this.lastError = null;
      this.ws.send(
        JSON.stringify({
          type: PACKET_TYPES.ATTACKER_NODE_HELLO,
          nodeId: this.nodeId,
        }),
      );
      this.emit("update", this.snapshot());
    });

    this.ws.on("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch (_e) {
        return;
      }

      if (
        msg.type === WS_EVENTS.ATTACKER_DEMO_SETTINGS_UPDATED &&
        msg.settings
      ) {
        this.authenticated = true;
        this.settings = {
          attackerDemoEnabled: !!msg.settings.attackerDemoEnabled,
          coverTrafficEnabled: !!msg.settings.coverTrafficEnabled,
          coverTrafficIntervalMs: Number(
            msg.settings.coverTrafficIntervalMs || 1500,
          ),
          coverTrafficJitterMs: Number(
            msg.settings.coverTrafficJitterMs || 1000,
          ),
          coverTrafficRatio: Number(msg.settings.coverTrafficRatio || 3),
        };
        this.emit("update", this.snapshot());
        this.simulateGlobalCoverTraffic();
        return;
      }

      if (msg.type === WS_EVENTS.ATTACKER_DEMO_PACKET && msg.packet) {
        this.onPacket(msg.packet);
      }
    });

    this.ws.on("close", () => {
      this.connected = false;
      this.authenticated = false;
      this.emit("update", this.snapshot());
      this.scheduleReconnect();
    });

    this.ws.on("error", (err) => {
      this.lastError = err && err.message ? err.message : "WebSocket error";
      this.emit("update", this.snapshot());
    });
  }

  simulateGlobalCoverTraffic() {
    if (this._simTimer) clearTimeout(this._simTimer);
    if (!this.settings || !this.settings.coverTrafficEnabled) return;

    const interval = this.settings.coverTrafficIntervalMs || 1500;
    const jitter = this.settings.coverTrafficJitterMs || 1000;
    const delay = interval + Math.random() * jitter;

    this._simTimer = setTimeout(() => {
      if (this.settings && this.settings.coverTrafficEnabled) {
        const ratio = this.settings.coverTrafficRatio || 3;
        for (let i = 0; i < ratio; i++) {
          this.onPacket({
            packetId: `PKT-${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
            type: "COVER_TRAFFIC",
            roomId: `ROOM-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
            fromUserId: `USR-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
            toUserId: "-",
            sizeBytes: Math.floor(Math.random() * 500) + 120,
            isCover: true,
            createdAt: new Date().toISOString()
          });
        }
      }
      this.simulateGlobalCoverTraffic();
    }, delay);
  }

  scheduleReconnect() {
    if (this._reconnectTimer) return;
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      this.connect();
    }, 1500);
  }

  onPacket(packet) {
    this.stats.totalPackets += 1;
    if (packet.isCover) {
      this.stats.coverPackets += 1;
    } else {
      this.stats.realPackets += 1;
    }

    let decryptStatus = "skipped";
    let decryptedPreview = "";

    if (process.env.DEMO_SHARED_KEY) {
      if (!packet.isCover) {
        try {
          const plain = decryptText(packet);
          this.stats.decryptionSuccess += 1;
          decryptStatus = "ok";
          decryptedPreview = String(plain).slice(0, 120);
        } catch (_e) {
          this.stats.decryptionFailed += 1;
          decryptStatus = "failed";
          decryptedPreview = "[decrypt-failed]";
        }
      } else {
        this.stats.decryptionSuccess += 1;
        decryptStatus = "ok";
        const tacticalTerms = [
          "UPLINK_SYNC",
          "NODE_HB",
          "ROUTING_ACK",
          "OP_TRACE",
          "SIG_ECHO",
          "TELEMETRY_DATA",
          "SENSE_ID",
          "GHOST_RELAY",
        ];
        const t1 =
          tacticalTerms[Math.floor(Math.random() * tacticalTerms.length)];
        const t2 =
          tacticalTerms[Math.floor(Math.random() * tacticalTerms.length)];
        const fakeHex = Math.random().toString(16).slice(2, 8).toUpperCase();
        decryptedPreview = `<0x${fakeHex}> [${t1}] ... obfuscated_payload ... [${t2}] <EOF>`;
      }
    }

    this.recentPackets.unshift({
      time: packet.createdAt || new Date().toISOString(),
      packetId: packet.packetId,
      type: packet.type,
      roomId: packet.roomId || "-",
      fromUserId: packet.fromUserId || "-",
      toUserId: packet.toUserId || "-",
      sizeBytes: Number(packet.sizeBytes || 0),
      isCover: !!packet.isCover,
      decryptStatus,
      decryptedPreview,
    });

    if (this.recentPackets.length > 500) {
      this.recentPackets.length = 500;
    }

    this.emit("update", this.snapshot());
  }

  clear() {
    this.stats = {
      totalPackets: 0,
      realPackets: 0,
      coverPackets: 0,
      decryptionSuccess: 0,
      decryptionFailed: 0,
    };
    this.recentPackets = [];
    this.emit("update", this.snapshot());
  }

  snapshot() {
    const ratio = this.stats.coverPackets / Math.max(this.stats.realPackets, 1);
    const confidence = this.settings.coverTrafficEnabled
      ? ratio >= 3
        ? "LOW"
        : "MEDIUM"
      : "HIGH";
    return {
      connected: this.connected,
      authenticated: this.authenticated,
      tlsWss: this.mainWsUrl.startsWith("wss://") ? "WSS" : "WS",
      demoLeakedKeyMode: !!process.env.DEMO_SHARED_KEY,
      confidence,
      settings: this.settings,
      stats: this.stats,
      packets: this.recentPackets,
      lastError: this.lastError,
    };
  }

  stop() {
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this.ws && this.ws.readyState <= 1) {
      try {
        this.ws.close();
      } catch (_e) {}
    }
  }
}

module.exports = { AttackerDemoClient };
