document.addEventListener('DOMContentLoaded', () => {
  // Sidebar Collapse Logic
  const sidebarBtn = document.getElementById('toggleSidebarBtn');
  const sidebar = document.getElementById('appSidebar');
  if (sidebarBtn && sidebar) {
    sidebarBtn.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
    });
  }

  // Session Clock
  const clockEl = document.getElementById('clock');
  if (clockEl) {
    let seconds = 0;
    setInterval(() => {
      seconds++;
      const hrs = String(Math.floor(seconds / 3600)).padStart(2, '0');
      const mins = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
      const secs = String(seconds % 60).padStart(2, '0');
      clockEl.textContent = `${hrs}:${mins}:${secs}`;
    }, 1000);
  }

  // Tab Navigation
  const tabLinks = document.querySelectorAll('.tab-link');
  const tabContents = document.querySelectorAll('.tab-content');

  tabLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      // Remove active from all
      tabLinks.forEach(l => l.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      // Add to clicked
      link.classList.add('active');
      const targetId = link.getAttribute('data-target');
      const target = document.getElementById(targetId);
      if (target) target.classList.add('active');
    });
  });

  // Socket.io Init
  const socket = (typeof io === 'function') ? io() : { on() {}, emit() {} };
  const currentUser = window.currentUserContext;

  // --- Real-time Chat (legacy demo mode only; /public/chat.js handles real ws room chat) ---
  const chatThread = document.getElementById('chatThread');
  const chatInput = document.getElementById('chatInput');
  const sendBtn = document.getElementById('sendBtn');
  const useRealWsChat = !!window.EPSI_CHAT;

  const appendMessage = (msg) => {
    if (!chatThread) return;
    const isSent = msg.sender === currentUser?.name;
    const div = document.createElement('div');
    div.className = `msg ${isSent ? 'msg-sent' : 'msg-received'}`;
    div.innerHTML = `
      <div class="msg-meta">
        <span>${msg.sender}</span>
        <span>${msg.timestamp}</span>
      </div>
      <div class="msg-body">
        ${msg.body} <i class="fa-solid fa-lock text-green ml-2" title="Encrypted"></i>
      </div>
    `;
    chatThread.appendChild(div);
    chatThread.scrollTop = chatThread.scrollHeight;
  };

  // Fetch initial messages via API
  if (chatThread && !useRealWsChat) {
    fetch('/api/messages')
      .then(res => res.json())
      .then(msgs => {
        chatThread.innerHTML = ''; // clear mock
        msgs.forEach(appendMessage);
      })
      .catch(() => {});
  }

  if (sendBtn && !useRealWsChat) {
    sendBtn.addEventListener('click', () => {
      const body = chatInput.value.trim();
      if (body) {
        const payload = {
          sender: currentUser?.name || 'User',
          body,
          timestamp: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
          encrypted: true
        };
        socket.emit('send_message', payload);
        chatInput.value = '';
      }
    });

    chatInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') sendBtn.click();
    });
  }

  if (!useRealWsChat) {
    socket.on('receive_message', (msg) => {
      appendMessage(msg);
    });
  }

  // --- Breach Simulation ---
  const simulateBtn = document.getElementById('simulateBreachBtn');
  if (simulateBtn) {
    simulateBtn.addEventListener('click', () => {
      fetch('/breach/simulate', { method: 'POST' });
    });
  }

  // Audio Context for Beep
  const playBeep = () => {
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const oscillator = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();
      oscillator.type = 'square';
      oscillator.frequency.setValueAtTime(880, audioCtx.currentTime); // 880Hz
      gainNode.gain.setValueAtTime(0.1, audioCtx.currentTime);
      oscillator.connect(gainNode);
      gainNode.connect(audioCtx.destination);
      oscillator.start();
      setTimeout(() => oscillator.stop(), 500);
    } catch (e) {
      console.log('Audio playback blocked by browser');
    }
  };

  // 1. Breach Initiated
  socket.on('breach_event', (data) => {
    playBeep();
    
    // Show Banner
    const banner = document.getElementById('breach-banner');
    banner.classList.remove('hidden');
    banner.classList.remove('animate__slideOutUp');
    banner.classList.add('animate__animated', 'animate__slideInDown');

    // Update Status Pill
    const statusPill = document.getElementById('encryption-status');
    statusPill.className = 'status-pill status-red';
    statusPill.innerHTML = '<span class="dot"></span> <span class="status-text">Breach Detected</span>';

    // Add Overlay to Chat
    if (chatThread && !document.querySelector('.invalid-overlay')) {
      const overlay = document.createElement('div');
      overlay.className = 'invalid-overlay';
      overlay.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>&nbsp;SESSION FROZEN: BREACH PROTOCOL';
      chatThread.appendChild(overlay);
      
      // Disable inputs
      if(chatInput) chatInput.disabled = true;
      if(sendBtn) sendBtn.disabled = true;
    }

    // Update Visualizer Nodes - All systems reflect
    document.querySelectorAll('.vis-node').forEach(node => {
      node.classList.add('breach-alert');
    });

    // Append to breach log if on admin pg
    const logBox = document.getElementById('breachLogBody');
    if (logBox) {
      const tr = document.createElement('tr');
      tr.className = 'animate__animated animate__fadeIn bg-red';
      tr.innerHTML = `
        <td class="text-gray">${data.timestamp.replace('T', ' ').substring(0, 16)}</td>
        <td>AI Detection</td>
        <td class="mono-text">Unknown</td>
        <td><span class="badge bg-red">High</span></td>
        <td class="status-cell"><i class="fa-solid fa-triangle-exclamation text-red"></i> Active</td>
      `;
      logBox.insertBefore(tr, logBox.firstChild);
    }
  });

  // 2. TLS Rotating
  socket.on('tls_rotating', () => {
    const statusPill = document.getElementById('encryption-status');
    statusPill.className = 'status-pill status-amber';
    statusPill.innerHTML = '<i class="fa-solid fa-arrow-rotate-right fa-spin"></i> <span class="status-text">Rotating TLS…</span>';
    
    const statusBadge = document.getElementById('cert-status-badge');
    if (statusBadge) {
      statusBadge.className = 'badge bg-amber';
      statusBadge.innerHTML = '<i class="fa-solid fa-arrow-rotate-right fa-spin"></i> Rotating';
    }
  });

  // 3. TLS Restored
  socket.on('tls_restored', (data) => {
    // Hide Banner
    const banner = document.getElementById('breach-banner');
    banner.classList.remove('animate__slideInDown');
    banner.classList.add('animate__slideOutUp');
    setTimeout(() => { banner.classList.add('hidden'); }, 1000);


    // Remove Chat Overlay and Clear Chat History Natively
    if (chatThread) {
      chatThread.innerHTML = ''; // Wipe chat permanently for dynamic ephemerality
      if(chatInput) chatInput.disabled = false;
      if(sendBtn) sendBtn.disabled = false;
    }

    // Update Cert View
    if (document.getElementById('cert-serial')) {
      document.getElementById('cert-serial').textContent = data.newSerial;
      document.getElementById('cert-valid').textContent = data.validFrom;
      document.getElementById('cert-expires').textContent = data.expires;
      
      const statusBadge = document.getElementById('cert-status-badge');
      statusBadge.className = 'badge bg-green';
      statusBadge.textContent = 'Active';

      const leaf = document.getElementById('leaf-node');
      leaf.classList.remove('active-leaf');
      void leaf.offsetWidth; // trigger reflow
      leaf.classList.add('active-leaf');
    }

    // Restore All Visualizer Nodes
    document.querySelectorAll('.vis-node').forEach(node => {
      node.classList.remove('breach-alert');
    });

    // Update Log Status
    const logBox = document.getElementById('breachLogBody');
    if (logBox && logBox.firstChild) {
      logBox.firstChild.classList.remove('bg-red');
      logBox.firstChild.querySelector('.status-cell').innerHTML = '<i class="fa-solid fa-check text-green"></i> Resolved';
    }
  });

  // Action Buttons Interactivity (Visual only)
  document.querySelectorAll('.simulate-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const target = e.currentTarget;
      const action = target.getAttribute('data-action');
      const tr = target.closest('tr');
      
      if (action === 'suspend' || action === 'logout') {
        const statusBadge = tr.querySelector('.badge');
        statusBadge.className = 'badge bg-red';
        statusBadge.innerHTML = '<i class="fa-solid fa-ban"></i> Suspended';
      }
      if (action === 'revoke') {
        tr.querySelector('.token-col').textContent = '—';
      }
    });
  });

  // --- Map Integration ---
  const mapContainer = document.getElementById('investigationMap');
  if (mapContainer && typeof L !== 'undefined') {
    // Init Leaflet map, default roughly over central ocean or Europe
    const map = L.map('investigationMap').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18,
      attribution: '© OpenStreetMap'
    }).addTo(map);

    let currentMarker = null;

    // Listeners for rows
    document.querySelectorAll('#breachLogBody .clickable-row').forEach(row => {
      row.addEventListener('click', () => {
        const ip = row.getAttribute('data-ip');
        const anomalyType = row.getAttribute('data-type');
        
        // Highlight clicked row locally
        document.querySelectorAll('#breachLogBody tr').forEach(r => r.style.background = '');
        row.style.background = 'rgba(16, 185, 129, 0.1)';

        document.getElementById('mapCountry').textContent = 'Querying API...';
        
        fetch('http://ip-api.com/json/' + ip)
          .then(r => r.json())
          .then(data => {
            if(data.status === 'success') {
              document.getElementById('mapCountry').textContent = data.country || 'Unknown';
              document.getElementById('mapIsp').textContent = data.isp || 'Unknown';
              document.getElementById('mapAnomaly').textContent = anomalyType;
              
              if(currentMarker) map.removeLayer(currentMarker);

              // Create Custom Tactical Icon
              const tacticalIcon = L.divIcon({
                className: 'pulse-point', // Reuse existing CSS class for pulsing
                iconSize: [12, 12]
              });

              currentMarker = L.marker([data.lat, data.lon], {icon: tacticalIcon}).addTo(map);
              map.flyTo([data.lat, data.lon], 5, { duration: 1.5 });
              currentMarker.bindPopup(`<strong>Target Data</strong><br>IP: ${ip}<br>ISP: ${data.isp}`).openPopup();
            } else {
              document.getElementById('mapCountry').textContent = 'Lookup Failed';
            }
          }).catch(err => {
            document.getElementById('mapCountry').textContent = 'API Error';
          });
      });
    });
  }

});
