import { loadLeaderboard } from './storage.js';

const NETWORK_META = {
  provider: { label: 'Provider Network', icon: '🌐', color: '#7ec8ff' },
  corp: { label: 'Corporate IT', icon: '🏢', color: '#caa8ff' },
  ot: { label: 'ICS / Power Plant OT', icon: '⚙️', color: '#ffcf84' },
  drone: { label: 'DroneOps / Secure Lab', icon: '🛰️', color: '#84f7cc' }
};

const PLATFORM_PLAYBOOK = {
  windows: {
    icon: '🪟',
    checks: ['Registry Run keys', 'Task Scheduler', 'SMB shares', 'Domain trust / GPO drift'],
    tools: {
      targeted: { name: 'PowerShell + Sysmon', command: 'powershell -NoProfile "Get-ScheduledTask | ? {$_.TaskName -match \"update|svc\"}"' },
      aggressive: { name: 'Nmap SMB NSE', command: 'nmap -Pn -sV --script smb-enum-shares,smb-os-discovery <target-ip>' },
      stealth: { name: 'wevtutil + AD query', command: 'wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:30 /f:text' }
    },
    jokes: [
      'Interesting key found: `0x00beef_powershell.exe`. Follow the rabbit hole?',
      'CPU is screaming like a kettle. Did anyone launch a crypto rocket?'
    ]
  },
  linux: {
    icon: '🐧',
    checks: ['Cron persistence', 'systemd services', 'SSH keys', 'sudoers abuse'],
    tools: {
      targeted: { name: 'systemctl + journalctl', command: 'systemctl list-unit-files --state=enabled && journalctl -u ssh --since -2h' },
      aggressive: { name: 'Nmap service scan', command: 'nmap -Pn -sC -sV --open <target-ip>' },
      stealth: { name: 'auditd tail', command: 'ausearch -m USER_CMD,EXECVE -ts recent | tail -n 30' }
    },
    jokes: [
      'Cron spawned at 03:13 again. Either malware or your server has insomnia.',
      'Load average went gym mode overnight. Who invited a miner?'
    ]
  },
  ot: {
    icon: '🏭',
    checks: ['PLC program drift', 'Historian writes', 'Engineering workstation sessions', 'Unsafe process changes'],
    tools: {
      targeted: { name: 'Read-only OT collector', command: 'ot-inspect --mode read-only --asset <ot-host>' },
      aggressive: { name: 'Protocol sweep (careful)', command: 'nmap -sT -Pn -p 502,44818,20000 <ot-subnet>' },
      stealth: { name: 'Historian diff', command: 'historiandiff --window 30m --anomaly-threshold low' }
    },
    jokes: [
      'Valve opened itself at 2AM. Ghost shift or bad logic write?',
      'Historian trend looks like a heart monitor in a horror movie.'
    ]
  },
  appliance: {
    icon: '📡',
    checks: ['API key rotation', 'Firmware hashes', 'Control-channel ACL', 'Build pipeline provenance'],
    tools: {
      targeted: { name: 'API + config pull', command: 'curl -s https://<host>/api/v1/config | jq .security' },
      aggressive: { name: 'Nmap + script sweep', command: 'nmap -Pn -sV --script http-enum,ssl-cert <target-ip>' },
      stealth: { name: 'Log delta query', command: 'jq ".events[] | select(.severity==\"warn\")" /var/log/device-audit.json' }
    },
    jokes: [
      'Firmware hash changed on Friday night. Very normal. Totally.',
      'Somebody keeps calling this box from nowhere. It answers every time.'
    ]
  }
};

const EASY_MISSIONS = [
  'Where is my USB? Trace the last connected device and recover the file.',
  'Why can’t I access Instagram from office Wi-Fi?',
  'Laptop fans sound like helicopter blades. Find the process.',
  'Printer is possessed again. Who keeps submitting 900-page jobs?'
];

export function bindUI({ onChoose, onReplay, onExport, onToggleMap, onDifficultyChange, onMalwareAction }) {
  document.getElementById('newSeedBtn').onclick = () => onReplay('new');
  document.getElementById('sameSeedBtn').onclick = () => onReplay('same');
  document.getElementById('exportBtn').onclick = onExport;
  document.getElementById('toggleMapBtn').onclick = onToggleMap;
  document.getElementById('difficultyMode').onchange = (e) => onDifficultyChange(e.target.value);
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-malware-host]');
    if (!btn) return;
    onMalwareAction(btn.dataset.malwareHost, btn.dataset.action);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key >= '1' && e.key <= '9') onChoose(Number(e.key) - 1);
  });
}

export function render(game, scenario, showMap = false, difficulty = 'expert') {
  const state = game.state;
  const node = scenario.nodes[state.nodeId];
  const context = deriveNodeContext(game, node);
  document.getElementById('seedValue').textContent = game.seed;
  document.getElementById('difficultyMode').value = difficulty;
  document.getElementById('timerValue').textContent = `${String(Math.floor(state.timeLeftSec / 60)).padStart(2, '0')}:${String(state.timeLeftSec % 60).padStart(2, '0')}`;
  document.getElementById('scoreValue').textContent = state.score;
  meter('noise', state.noise);
  meter('ot', state.otRisk);
  document.getElementById('nodeTitle').textContent = node.title;
  document.getElementById('nodeText').textContent = node.text;
  document.getElementById('effectsText').textContent = state.effectMessage;

  renderContextPanel(context, difficulty, game.seed);
  renderChoices(game.getAvailableOptions(), context, difficulty);
  renderNetworkMap(state.access);
  renderInventory(state, game.seededHosts?.hostMap || []);
  renderMalwarePanel(state.malwareSightings || {}, game.seededHosts?.hostMap || []);
  renderCommand(node.commandPreview || 'Select a network action and tool profile.');
  renderLeaderboard();
  renderDevMap(game, showMap);

  if (state.sessionEnded) {
    document.getElementById('effectsText').textContent = `Session ended: ${state.ending}. Hosts found: ${state.foundHosts.length}.`;
  }
}

function deriveNodeContext(game, node) {
  const nodeText = `${node.id} ${node.title} ${node.text}`.toLowerCase();
  const network = Object.keys(NETWORK_META).find((n) => nodeText.includes(n)) || 'corp';
  const hosts = (game.seededHosts?.hostMap || []).filter((h) => h.network === network);
  const selectedHost = hosts[0] || { id: `${network}-target`, platform: 'linux', role: 'server' };
  const platform = PLATFORM_PLAYBOOK[selectedHost.platform] ? selectedHost.platform : network === 'ot' ? 'ot' : 'appliance';
  return { network, host: selectedHost, playbook: PLATFORM_PLAYBOOK[platform] };
}

function meter(prefix, v) {
  document.getElementById(`${prefix}Meter`).value = v;
  document.getElementById(`${prefix}Value`).textContent = `${v}/10`;
}

function renderContextPanel(context, difficulty, seed) {
  const meta = NETWORK_META[context.network];
  const checks = (difficulty === 'easy' ? context.playbook.checks.slice(0, 2) : context.playbook.checks)
    .map((c) => `<li>${c}</li>`).join('');
  const joke = pickBySeed(context.playbook.jokes, seed);
  const funQuest = pickBySeed(EASY_MISSIONS, seed);
  document.getElementById('nodeContext').innerHTML = `
    <div class="context-chip" style="--chip:${meta.color}">${meta.icon} ${meta.label}</div>
    <div class="context-chip">${context.playbook.icon} ${context.host.id}</div>
    <p class="dark-brief">🕶️ ${joke}</p>
    ${difficulty === 'easy' ? `<p class="fun-brief">🎮 Casual mission: ${funQuest}</p>` : ''}
    <ul>${checks}</ul>
  `;
}

function renderChoices(options, context, difficulty) {
  const c = document.getElementById('choices');
  c.innerHTML = '';
  const capped = options.slice(0, difficulty === 'easy' ? 2 : 3);
  capped.forEach((opt, i) => {
    const mode = pickMode(opt.label);
    const tool = context.playbook.tools[mode];
    const b = document.createElement('button');
    b.className = 'choice-btn';
    b.innerHTML = `
      <div class="choice-top"><span>[${i + 1}] ${opt.label}</span><span class="time-pill">-${opt.timeCostSec || 0}s</span></div>
      <div class="choice-meta">${difficulty === 'easy' ? 'Guided move' : tool.name}</div>
      <code>${shorten(difficulty === 'easy' ? userFriendlyHint(opt.label) : tool.command, 64)}</code>
    `;
    b.onmouseenter = () => renderCommand(difficulty === 'easy' ? userFriendlyHint(opt.label) : tool.command);
    b.onfocus = () => renderCommand(difficulty === 'easy' ? userFriendlyHint(opt.label) : tool.command);
    b.onclick = () => {
      renderCommand(`> ${difficulty === 'easy' ? userFriendlyHint(opt.label) : tool.command}`);
      window.__choose(i);
    };
    c.appendChild(b);
  });
}

function userFriendlyHint(label) {
  const lower = label.toLowerCase();
  if (lower.includes('dns')) return 'Open DNS dashboard and check suspicious spikes.';
  if (lower.includes('domain')) return 'Check who changed domain settings recently.';
  if (lower.includes('ot')) return 'Use safe mode and inspect process anomalies.';
  return 'Follow the hint card, click investigate, then isolate anything weird.';
}

function pickMode(label = '') {
  const lower = label.toLowerCase();
  if (lower.includes('aggressive') || lower.includes('full sweep')) return 'aggressive';
  if (lower.includes('stealth')) return 'stealth';
  return 'targeted';
}

function renderNetworkMap(access) {
  const el = document.getElementById('networkMap');
  const node = (key, x, y) => {
    const meta = NETWORK_META[key];
    const locked = !access[key];
    return `<g>
      <circle cx="${x}" cy="${y}" r="42" fill="${locked ? '#3a2e3f' : '#223960'}" stroke="${meta.color}" stroke-width="2"></circle>
      <text x="${x}" y="${y - 6}" text-anchor="middle" font-size="19">${meta.icon}</text>
      <text x="${x}" y="${y + 14}" text-anchor="middle" font-size="11" fill="#dce9ff">${key.toUpperCase()}</text>
      <text x="${x + 25}" y="${y - 20}" font-size="12">${locked ? '🔒' : '🟢'}</text>
    </g>`;
  };

  el.innerHTML = `<svg viewBox="0 0 420 300" class="subnet-svg" role="img" aria-label="Subnet relation map">
    <defs><linearGradient id="linegrad" x1="0" x2="1"><stop offset="0" stop-color="#7cd7ff"/><stop offset="1" stop-color="#d0a4ff"/></linearGradient></defs>
    <rect x="162" y="116" width="96" height="70" rx="12" fill="#1e2b49" stroke="#7cd7ff"/>
    <text x="210" y="145" text-anchor="middle" font-size="20">🛡️</text>
    <text x="210" y="165" text-anchor="middle" font-size="12" fill="#dce9ff">SOC</text>
    <line x1="210" y1="116" x2="210" y2="62" stroke="url(#linegrad)" stroke-width="3"/>
    <line x1="162" y1="151" x2="90" y2="151" stroke="url(#linegrad)" stroke-width="3"/>
    <line x1="258" y1="151" x2="330" y2="151" stroke="url(#linegrad)" stroke-width="3"/>
    <line x1="210" y1="186" x2="210" y2="240" stroke="url(#linegrad)" stroke-width="3"/>
    ${node('provider', 210, 50)}
    ${node('corp', 80, 150)}
    ${node('drone', 340, 150)}
    ${node('ot', 210, 250)}
  </svg>`;
}

function renderInventory(state, hostMap) {
  const icons = { windows: '🪟', linux: '🐧', ot: '🏭', appliance: '📡' };
  const hostBadges = state.foundHosts.map((id) => {
    const host = hostMap.find((h) => h.id === id);
    return `<span class="host-pill">${icons[host?.platform] || '🧩'} ${id}</span>`;
  }).join(' ');

  document.getElementById('inventory').innerHTML = `
    <p><strong>Items:</strong> ${state.inventory.join(', ') || 'None'}</p>
    <p><strong>Found Hosts (${state.foundHosts.length}):</strong></p>
    <div class="host-list">${hostBadges || '<span class="host-pill">None</span>'}</div>
  `;
}

function renderMalwarePanel(sightings, hostMap) {
  const entries = Object.entries(sightings);
  const byId = Object.fromEntries(hostMap.map((h) => [h.id, h]));
  document.getElementById('malwarePanel').innerHTML = entries.length === 0
    ? '<p class="malware-empty">No active malware found yet.</p>'
    : entries.map(([hostId, m]) => {
      const host = byId[hostId];
      const icon = host?.platform === 'windows' ? '🪟' : host?.platform === 'linux' ? '🐧' : host?.platform === 'ot' ? '🏭' : '📡';
      return `<article class="malware-card">
        <div><strong>${icon} ${hostId}</strong> <span class="status ${m.status}">${m.status}</span></div>
        <div class="threat">${m.threat}</div>
        <div class="malware-actions">
          <button data-malware-host="${hostId}" data-action="analyze" type="button">Analyze</button>
          <button data-malware-host="${hostId}" data-action="quarantine" type="button">Quarantine</button>
          <button data-malware-host="${hostId}" data-action="eradicate" type="button">Eradicate</button>
        </div>
      </article>`;
    }).join('');
}

function renderCommand(text) {
  document.getElementById('commandBuilder').textContent = text.length > 120 ? `${text.slice(0, 117)}...` : text;
}

function renderLeaderboard() {
  const board = loadLeaderboard();
  document.getElementById('leaderboard').innerHTML = board.map((e) => `<li>${e.name} — ${e.score} (${e.timeLeftSec}s)</li>`).join('');
}

function renderDevMap(game, show) {
  const el = document.getElementById('devMap');
  if (!show) { el.classList.add('hidden'); return; }
  el.classList.remove('hidden');
  const options = game.getAvailableOptions();
  el.innerHTML = `<div><strong>Current:</strong> ${game.state.nodeId}</div><div><strong>Neighbors:</strong> ${options.map((o) => o.next).join(', ')}</div>`;
}

function pickBySeed(items, seed) {
  const num = [...seed].reduce((acc, c) => acc + c.charCodeAt(0), 0);
  return items[num % items.length];
}

function shorten(text, max) {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}
