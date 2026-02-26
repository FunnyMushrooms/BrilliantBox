import { loadLeaderboard } from './storage.js';

const NETWORK_META = {
  provider: { label: 'Domain & Public Services', icon: '🌐', color: '#7ec8ff' },
  corp: { label: 'Corporate Domain', icon: '🏢', color: '#caa8ff' },
  ot: { label: 'ICS / Power Grid', icon: '⚙️', color: '#ffcf84' },
  drone: { label: 'Military UAV Network', icon: '🛰️', color: '#84f7cc' }
};

const PLATFORM_PLAYBOOK = {
  windows: {
    icon: '🪟',
    checks: ['Registry Run keys', 'Task Scheduler', 'SMB shares', 'Domain trust / GPO drift'],
    tools: {
      targeted: { name: 'PowerShell process triage', command: 'Get-Process | Sort-Object CPU -Descending | Select -First 20' },
      aggressive: { name: 'Security event sweep', command: 'Get-WinEvent -LogName Security -MaxEvents 300 | ? Message -match "powershell|rundll32"' },
      stealth: { name: 'Signed binary check', command: 'Get-CimInstance Win32_Process | Select Name,ProcessId,CommandLine' }
    }
  },
  linux: {
    icon: '🐧',
    checks: ['Cron persistence', 'systemd services', 'SSH keys', 'sudoers abuse'],
    tools: {
      targeted: { name: 'User baseline review', command: 'cat /etc/passwd | tail -n 20; last -n 20' },
      aggressive: { name: 'Service + socket sweep', command: 'ps aux --sort=-%cpu | head -25; ss -plant' },
      stealth: { name: 'Exec audit trail', command: 'ausearch -m EXECVE -ts recent | tail -n 50' }
    }
  },
  ot: {
    icon: '🏭',
    checks: ['PLC program drift', 'Historian writes', 'Engineering workstation sessions', 'Unsafe process changes'],
    tools: {
      targeted: { name: 'Modbus read-only', command: 'modbus read 10.77.4.20:502 holding 40001 10' },
      aggressive: { name: 'Protocol anomaly review', command: 'ot-flow-review --ports 502,44818 --window 30m --show-writes' },
      stealth: { name: 'Historian divergence', command: 'historiandiff --window 2h --anomaly-threshold low' }
    }
  },
  appliance: {
    icon: '📡',
    checks: ['API key rotation', 'Firmware hashes', 'Control-channel ACL', 'Build pipeline provenance'],
    tools: {
      targeted: { name: 'Config security summary', command: 'curl -s https://<host>/api/v1/config | jq .security' },
      aggressive: { name: 'Route/config diff', command: 'netconf-diff --running --baseline --strict' },
      stealth: { name: 'Warning log lens', command: 'jq ".events[] | select(.severity==\"warn\")" /var/log/device-audit.json' }
    }
  }
};

const APP_WINDOWS = {
  provider: [
    { id: 'public-news', title: 'Public News Portal', hint: 'Homepage fails when DNS/feed channels are blocked.', body: '<h4>National News</h4><p>Status: <strong>Degraded</strong></p><p>Investigate DNS poisoning and provider-corp link.</p>' },
    { id: 'domain-banking', title: 'Domain Banking', hint: 'Payment widgets depend on provider + domain routes.', body: '<h4>Domain Bank</h4><p>Transfers queued. API timeout to core domain.</p>' }
  ],
  corp: [
    { id: 'hr-portal', title: 'HR Payroll App', hint: 'Breaks if SMB historian sync path is blocked unexpectedly.', body: '<h4>Payroll Console</h4><p>Warning: shared drive latency, suspicious macro in CV uploads.</p>' },
    { id: 'mil-website', title: 'Military Public Website', hint: 'Availability tied to provider feed and firewall route integrity.', body: '<h4>Public Affairs Site</h4><p>Intermittent outage reports from citizens.</p>' }
  ],
  ot: [
    { id: 'ics-panel', title: 'ICS Operations Panel', hint: 'Look for unsafe write activity and setpoint drift.', body: '<h4>Grid Panel</h4><p>Turbine setpoint variance above threshold.</p>' }
  ],
  drone: [
    { id: 'uav-stream', title: 'UAV Live Stream', hint: 'Drops when UAV relay path or process is disrupted.', body: '<h4>UAV Stream</h4><p>Packet jitter and partial frame loss detected.</p>' }
  ]
};

const FIREWALL_CASES = {
  'provider-corp': {
    routePrompt: 'There are a lot of routes flapping between CDN edges and corp DNS. Should we inspect this routing mess?',
    logPrompt: 'Big BGP/syslog file detected. It includes who touched route maps and remote peers.',
    clues: ['Unexpected prefix 10.44.0.0/16 injected from peer 185.17.44.9', 'Burst of updates exactly when portal outage started'],
    suspects: [
      { ip: '185.17.44.9', type: 'malicious', note: 'Unknown ASN, spoofed telemetry signatures.' },
      { ip: '52.19.31.6', type: 'normal', note: 'Known cloud resolver checks.' }
    ]
  },
  'corp-ot': {
    routePrompt: 'SMB historian sync routes are duplicated. Which path keeps OT stable and which path is attacker reroute?',
    logPrompt: 'Massive firewall export mentions odd write bursts to OT subnet.',
    clues: ['Repeated lateral traffic from 10.91.7.77 to OT gateway', 'Write attempts on port 445 + odd service account tokens'],
    suspects: [
      { ip: '10.91.7.77', type: 'malicious', note: 'Credential replay host behind compromised workstation.' },
      { ip: '10.12.2.33', type: 'normal', note: 'Legit backup service route.' }
    ]
  },
  'corp-drone': {
    routePrompt: 'Mission package routes are noisy. Should we untangle this before blocking traffic?',
    logPrompt: 'A giant transfer log shows payload signatures for drone builds.',
    clues: ['Unsigned package push from 172.23.99.41', 'Normal package mirror from 172.23.4.10'],
    suspects: [
      { ip: '172.23.99.41', type: 'malicious', note: 'Backdoored mission package distributor.' },
      { ip: '172.23.4.10', type: 'normal', note: 'Expected staging mirror.' }
    ]
  },
  'provider-drone': {
    routePrompt: 'UAV stream relay has route loops. Recovering stable routes might restore live feed first.',
    logPrompt: 'Traffic telemetry file is huge. It may reveal if packet loss is attack or normal burst.',
    clues: ['IP 104.23.201.7 caused 13k reset packets in 4 minutes', 'IP 198.51.100.24 is regular media CDN burst'],
    suspects: [
      { ip: '104.23.201.7', type: 'malicious', note: 'RST flood and spoofed headers.' },
      { ip: '198.51.100.24', type: 'normal', note: 'Expected high bitrate stream bursts.' }
    ]
  }
};

const firewallLabState = {};

const MACHINE_ACTIONS = {
  'corp-hr-01': [
    { id: 'audit-mail-rules', label: 'Audit HR mail forwarding rules', command: 'Get-InboxRule -Mailbox hr@corp.local' },
    { id: 'trace-route', label: 'Investigate network route (tracert)', command: 'tracert 10.10.66.77' }
  ],
  'corp-dc-01': [
    { id: 'reset-krbtgt', label: 'Reset compromised Kerberos trust', command: 'Reset-KrbtgtKeys -Force' },
    { id: 'aggressive-scan', label: 'Aggressive AD scan (high EDR risk)', command: 'nmap -p 1-65535 -T 4 corp-dc-01' }
  ],
  'corp-fs-02': [
    { id: 'restore-fileshare-acl', label: 'Restore FileServer ACL from backup', command: 'icacls \\corp-fs-02\\shared /restore backup.acl' },
    { id: 'proxy-cache-triage', label: 'Cross-check suspicious package origin', command: 'proxyctl cache audit --top-talkers' }
  ],
  'prov-dns-01': [
    { id: 'flush-dns-poison', label: 'Flush DNS poisoning artifacts', command: 'rndc flush && rndc reload' },
    { id: 'trace-route', label: 'Trace blocked public route', command: 'tracert 10.10.66.77' }
  ],
  'prov-fw-01': [
    { id: 'enable-fw-hunt', label: 'Enable firewall hunt monitor profile', command: 'fwctl profile threat-hunt --mode monitor' },
    { id: 'aggressive-scan', label: 'Aggressive edge scan (risk lockout)', command: 'nmap -p 1-65535 -T 4 prov-fw-01' }
  ],
  'prov-proxy-01': [
    { id: 'proxy-cache-triage', label: 'Investigate proxy cache anomalies', command: 'proxyctl cache audit --top-talkers' },
    { id: 'trace-route', label: 'Trace upstream route loops', command: 'tracert 10.10.66.77' }
  ],
  'ot-hmi-01': [
    { id: 'ot-safe-mode', label: 'Switch ICS to safe mode', command: 'scadactl set safety-mode on' },
    { id: 'isolate-substation-link', label: 'Isolate corp <-> substation link', command: 'gatewayctl isolate-link --peer corp' }
  ],
  'ot-historian-02': [
    { id: 'recover-historian-stream', label: 'Repair missing historian telemetry', command: 'historiandiff --repair --window 4h' },
    { id: 'trace-route', label: 'Trace OT relay route', command: 'tracert 10.10.66.77' }
  ],
  'ot-gateway-03': [
    { id: 'isolate-substation-link', label: 'Isolate suspicious OT peer', command: 'gatewayctl isolate-link --peer corp' },
    { id: 'enable-fw-hunt', label: 'Mirror traffic to firewall hunt mode', command: 'fwctl profile threat-hunt --mode monitor' }
  ],
  'drone-relay-01': [
    { id: 'rotate-uav-keys', label: 'Rotate UAV relay encryption keys', command: 'uavctl key-rotate --all-relays' },
    { id: 'aggressive-scan', label: 'Aggressive relay scan (risk mission outage)', command: 'nmap -p 1-65535 -T 4 drone-relay-01' }
  ],
  'drone-plan-02': [
    { id: 'rollback-flight-plan', label: 'Rollback suspicious flight plan', command: 'missionctl rollback --last-known-good' },
    { id: 'trace-route', label: 'Trace mission package route', command: 'tracert 10.10.66.77' }
  ],
  'drone-archive-03': [
    { id: 'quarantine-archive-packages', label: 'Quarantine unsigned UAV packages', command: 'archivectl quarantine --unsigned' },
    { id: 'proxy-cache-triage', label: 'Cross-check archive source via proxy', command: 'proxyctl cache audit --top-talkers' }
  ]
};


export function bindUI({ onChoose, onReplay, onExport, onToggleMap, onDifficultyChange, onMalwareAction, onJumpNode, onMachineOperation, onFirewallChange, onProcessAction }) {
  document.getElementById('newSeedBtn').onclick = () => onReplay('new');
  document.getElementById('sameSeedBtn').onclick = () => onReplay('same');
  document.getElementById('exportBtn').onclick = onExport;
  document.getElementById('toggleMapBtn').onclick = onToggleMap;
  document.getElementById('difficultyMode').onchange = (e) => onDifficultyChange(e.target.value);
  document.getElementById('mapZoom').oninput = (e) => {
    const zoom = Number(e.target.value) / 100;
    const map = document.querySelector('#networkMap .subnet-svg');
    if (map) map.style.transform = `scale(${zoom})`;
  };

  document.addEventListener('click', async (e) => {
    const malwareBtn = e.target.closest('[data-malware-host]');
    if (malwareBtn) return onMalwareAction(malwareBtn.dataset.malwareHost, malwareBtn.dataset.action);

    const jump = e.target.closest('[data-jump-node]');
    if (jump) return runTransition(`Switching to ${jump.dataset.jumpNode} ...`, () => onJumpNode(jump.dataset.jumpNode));

    const machineOpen = e.target.closest('[data-machine-open]');
    if (machineOpen) return openMachineModal(machineOpen.dataset.machineOpen, machineOpen.dataset.machineNode);

    const machineJump = e.target.closest('[data-machine-jump]');
    if (machineJump) return runTransition('Opening machine workspace ...', () => onJumpNode(machineJump.dataset.machineJump));

    const machineOp = e.target.closest('[data-machine-op]');
    if (machineOp) return runMachineOperation(machineOp.dataset.machineHost, machineOp.dataset.machineOp, onMachineOperation);

    const fwOpen = e.target.closest('[data-fw-open]');
    if (fwOpen) return openFirewallLab(fwOpen.dataset.fwOpen, onFirewallChange);

    const fwAction = e.target.closest('[data-fw-action-link]');
    if (fwAction) {
      await runTransition('Applying firewall policy change ...', () => onFirewallChange(fwAction.dataset.fwActionLink, fwAction.dataset.fwActionMode), 1200, 2000);
      return;
    }

    const fwPuzzle = e.target.closest('[data-fw-puzzle]');
    if (fwPuzzle) return runFirewallPuzzleStep(fwPuzzle.dataset.fwPuzzle, fwPuzzle.dataset.fwStep);

    const fwSuspect = e.target.closest('[data-fw-suspect-link]');
    if (fwSuspect) return inspectFirewallSuspect(fwSuspect.dataset.fwSuspectLink, fwSuspect.dataset.fwSuspectIp);

    const processLabBtn = e.target.closest('[data-open-process-lab]');
    if (processLabBtn) return openProcessLab(processLabBtn.dataset.openProcessLab, onProcessAction);

    const proc = e.target.closest('[data-proc-host]');
    if (proc) return runProcessAction(onProcessAction, proc.dataset.procHost, proc.dataset.procName, proc.dataset.procAction, proc.dataset.procVerdict);

    const appBtn = e.target.closest('[data-app-open]');
    if (appBtn) return openSiteModal(appBtn.dataset.appOpen, appBtn.dataset.appHint, appBtn.dataset.appBody);
  });

  document.getElementById('analysisCloseBtn').onclick = closeProcessModal;
  document.addEventListener('keydown', (e) => {
    if (e.key >= '1' && e.key <= '9') onChoose(Number(e.key) - 1);
    if (e.key === 'Escape') closeProcessModal();
  });
}

export function render(game, scenario, showMap = false, difficulty = 'expert') {
  const state = game.state;
  const node = scenario.nodes[state.nodeId];
  const context = deriveNodeContext(game, node);
  const firewallLinks = game.getFirewallLinks();
  window.__stateEvidence = state.evidence || { maliciousIps: [], executionPaths: [] };

  document.getElementById('seedValue').textContent = game.seed;
  document.getElementById('difficultyMode').value = difficulty;
  document.getElementById('timerValue').textContent = `${String(Math.floor(state.timeLeftSec / 60)).padStart(2, '0')}:${String(state.timeLeftSec % 60).padStart(2, '0')}`;
  document.getElementById('scoreValue').textContent = state.score;
  meter('noise', state.noise);
  meter('ot', state.otRisk);
  document.getElementById('nodeTitle').textContent = node.title;
  document.getElementById('nodeText').textContent = node.text;
  document.getElementById('effectsText').textContent = state.effectMessage;

  renderContextPanel(context, difficulty);
  renderChoices(node, game.getAvailableOptions(), context, difficulty);
  renderNetworkMap(game, state.access, firewallLinks);
  renderKillChain(state.killChain || { stages: [], revealed: [] }, state.evidence || { maliciousIps: [], executionPaths: [] });
  renderInventory(state, game.seededHosts?.hostMap || []);
  renderMalwarePanel(state.malwareSightings || {}, game.seededHosts?.hostMap || []);
  renderOpsPanel(context, firewallLinks);
  renderServiceWindows(context.network);
  renderGuidancePanel(game.getRemediationChecklist());
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
  const host = hosts.find((h) => h.id === node.machineId) || hosts[0] || { id: `${network}-target`, platform: 'linux', role: 'server', description: 'Generic target' };
  const playbook = PLATFORM_PLAYBOOK[host.platform] || PLATFORM_PLAYBOOK.appliance;
  return { network, host, playbook };
}

function meter(prefix, value) {
  document.getElementById(`${prefix}Meter`).value = value;
  document.getElementById(`${prefix}Value`).textContent = `${value}/10`;
}

function renderContextPanel(context, difficulty) {
  const meta = NETWORK_META[context.network];
  const checks = (difficulty === 'easy' ? context.playbook.checks.slice(0, 2) : context.playbook.checks)
    .map((c) => `<li>${c}</li>`).join('');
  document.getElementById('nodeContext').innerHTML = `
    <div class="context-chip" style="--chip:${meta.color}">${meta.icon} ${meta.label}</div>
    <div class="context-chip">${context.playbook.icon} ${context.host.id}</div>
    <p class="machine-brief"><strong>Role:</strong> ${context.host.role} — ${context.host.description || 'Machine-specific investigation target.'}</p>
    <ul>${checks}</ul>
    <div class="malware-actions"><button type="button" data-open-process-lab="${context.host.id}">Investigate Processes on ${context.host.id}</button></div>
  `;
}

function renderChoices(node, options, context, difficulty) {
  const c = document.getElementById('choices');
  c.innerHTML = '';

  if (node.id === 'start' || node.type === 'hub') {
    c.innerHTML = '<div class="choice-hint">🗺️ Use the visual network map (center) to open machines directly. No text-only pivot required.</div>';
    return;
  }

  const capped = options.slice(0, difficulty === 'easy' ? 2 : 3);
  capped.forEach((opt, i) => {
    const mode = pickMode(opt.label);
    const tool = context.playbook.tools[mode];
    const b = document.createElement('button');
    b.className = 'choice-btn';
    b.innerHTML = `
      <div class="choice-top"><span>[${i + 1}] ${opt.label}</span><span class="time-pill">${opt.timeCostSec || 10}s op</span></div>
      <div class="choice-meta">${tool.name}</div>
      <code>${shorten(tool.command, 90)}</code>
    `;
    b.onmouseenter = () => renderCommand(tool.command);
    b.onclick = () => runTransition('Executing analyst task ...', () => window.__choose(i));
    c.appendChild(b);
  });
}

function pickMode(label = '') {
  const lower = label.toLowerCase();
  if (lower.includes('aggressive') || lower.includes('full sweep') || lower.includes('disable')) return 'aggressive';
  if (lower.includes('stealth')) return 'stealth';
  return 'targeted';
}

function renderNetworkMap(game, access, links) {
  const el = document.getElementById('networkMap');
  const linkById = Object.fromEntries(links.map((l) => [l.id, l]));
  const hostMeta = Object.fromEntries((game.seededHosts?.hostMap || []).map((h) => [h.id, h]));
  window.__machineMeta = hostMeta;

  const machine = (x, y, hostId, nodeId, icon, label) => `
    <g class="map-machine" data-machine-open="${hostId}" data-machine-node="${nodeId}" transform="translate(${x},${y})">
      <rect width="86" height="54" rx="10"></rect>
      <text x="43" y="20" text-anchor="middle" font-size="18">${icon}</text>
      <text x="43" y="40" text-anchor="middle" font-size="10">${label}</text>
    </g>`;

  const fwKnob = (id, x, y) => {
    const status = linkById[id]?.status || 'allow';
    return `<g class="fw-knob ${status}" data-fw-open="${id}" transform="translate(${x},${y})">
      <circle r="11"></circle>
      <text y="3" text-anchor="middle" font-size="11">${status === 'block' ? '⛔' : status === 'monitor' ? '🟡' : '🟢'}</text>
    </g>`;
  };

  el.innerHTML = `<svg viewBox="0 0 1200 760" class="subnet-svg full-map" role="img" aria-label="Interactive topology">
    <rect x="18" y="18" width="1164" height="724" class="topo-bg"></rect>

    <rect x="250" y="40" width="700" height="200" class="zone-box"></rect>
    <rect x="70" y="260" width="350" height="250" class="zone-box"></rect>
    <rect x="780" y="280" width="340" height="240" class="zone-box"></rect>

    <line x1="340" y1="360" x2="560" y2="360" class="map-link"/>
    <line x1="850" y1="360" x2="640" y2="360" class="map-link"/>
    <line x1="600" y1="240" x2="600" y2="310" class="map-link"/>
    <line x1="600" y1="410" x2="600" y2="520" class="map-link"/>
    <line x1="260" y1="510" x2="560" y2="570" class="map-link"/>
    <line x1="960" y1="560" x2="640" y2="570" class="map-link"/>

    ${fwKnob('provider-corp', 500, 350)}
    ${fwKnob('provider-drone', 700, 350)}
    ${fwKnob('corp-drone', 600, 330)}
    ${fwKnob('corp-ot', 560, 535)}

    <text x="600" y="278" text-anchor="middle" class="zone-label">Router</text>
    <rect x="560" y="310" width="80" height="70" rx="8" class="soc-core" data-jump-node="start"></rect>
    <text x="600" y="346" text-anchor="middle" font-size="26">🛜</text>

    <text x="610" y="92" text-anchor="middle" class="zone-title">Provider / ICS</text>
    ${machine(360, 110, 'prov-dns-01', 'provider_dns', '🖥️', 'Control Station')}
    ${machine(556, 110, 'prov-fw-01', 'provider_router', '🧊', 'Controller')}
    ${machine(752, 110, 'prov-proxy-01', 'provider_proxy', '🗄️', 'PowerPlant')}

    <text x="240" y="308" text-anchor="middle" class="zone-title">Domain</text>
    ${machine(110, 330, 'corp-hr-01', 'corp_hr', '🖥️', 'HR')}
    ${machine(230, 330, 'corp-dc-01', 'corp_dc', '🖥️', 'HQ')}
    ${machine(100, 420, 'corp-fs-02', 'corp_fs', '🏦', 'Banking App')}
    ${machine(240, 420, 'corp-fs-02', 'corp_fs', '💾', 'FileServer')}

    <text x="950" y="322" text-anchor="middle" class="zone-title">Military</text>
    ${machine(840, 340, 'drone-plan-02', 'drone_plan', '💻', 'Engineer 1')}
    ${machine(980, 340, 'drone-relay-01', 'drone_relay', '✈️', 'UAV')}
    ${machine(900, 430, 'drone-archive-03', 'drone_archive', '🗼', 'Station')}

    <rect x="560" y="530" width="80" height="70" rx="8" class="zone-box firewall" data-fw-open="provider-corp"></rect>
    <text x="600" y="568" text-anchor="middle" font-size="28">🧱</text>
    <text x="600" y="607" text-anchor="middle" class="zone-label">Firewall</text>

    <text x="940" y="640" text-anchor="middle" font-size="42">🌍</text>
    <text x="940" y="670" text-anchor="middle" class="zone-label">Internet</text>
  </svg>`;

  const initialZoom = Number(document.getElementById('mapZoom')?.value || 120) / 100;
  const map = document.querySelector('#networkMap .subnet-svg');
  if (map) map.style.transform = `scale(${initialZoom})`;
}

function renderKillChain(killChain, evidence = { maliciousIps: [], executionPaths: [] }) {
  const chain = document.getElementById('killChainPanel');
  const clues = [...(evidence.maliciousIps || []), ...(evidence.executionPaths || [])];
  chain.innerHTML = `
    <div class="kill-flow">${killChain.stages.map((stage, i) => {
      const unlocked = killChain.revealed.includes(stage);
      const label = unlocked ? stage : '???';
      const clue = unlocked && clues[i] ? clues[i] : (unlocked ? 'opened' : '? evidence');
      return `<div class="flow-stage ${unlocked ? 'on' : 'off'}"><span class="flow-title">${label}</span><span class="flow-evidence">${clue}</span></div>${i < killChain.stages.length - 1 ? '<span class="flow-arrow">→</span>' : ''}`;
    }).join('')}</div>
  `;
}

function renderInventory(state, hostMap) {
  const icons = { windows: '🪟', linux: '🐧', ot: '🏭', appliance: '📡' };
  const hostBadges = state.foundHosts.map((id) => {
    const host = hostMap.find((h) => h.id === id);
    return `<span class="host-pill">${icons[host?.platform] || '🧩'} ${id}</span>`;
  }).join(' ');
  document.getElementById('inventory').innerHTML = `<p><strong>Items:</strong> ${state.inventory.join(', ') || 'None'}</p><p><strong>Found Hosts (${state.foundHosts.length}):</strong></p><div class="host-list">${hostBadges || '<span class="host-pill">None</span>'}</div>`;
}

function renderMalwarePanel(sightings, hostMap) {
  const entries = Object.entries(sightings);
  const byId = Object.fromEntries(hostMap.map((h) => [h.id, h]));
  document.getElementById('malwarePanel').innerHTML = entries.length === 0
    ? '<p class="malware-empty">No active malware found yet.</p>'
    : entries.map(([hostId, m]) => {
      const host = byId[hostId];
      const icon = host?.platform === 'windows' ? '🪟' : host?.platform === 'linux' ? '🐧' : host?.platform === 'ot' ? '🏭' : '📡';
      return `<article class="malware-card"><div><strong>${icon} ${hostId}</strong> <span class="status ${m.status}">${m.status}</span></div><div class="threat">${m.threat}</div><div class="malware-actions"><button data-malware-host="${hostId}" data-action="analyze" type="button">Analyze</button><button data-malware-host="${hostId}" data-action="quarantine" type="button">Quarantine</button><button data-malware-host="${hostId}" data-action="eradicate" type="button">Eradicate</button></div></article>`;
    }).join('');
}

function renderOpsPanel(context, firewallLinks) {
  const related = firewallLinks.filter((l) => l.a === context.network || l.b === context.network);
  const cards = related.map((link) => `<article class="firewall-card ${link.status}"><div><strong>${link.id}</strong></div><div class="threat">${link.service} • ${link.status}</div><div class="malware-actions"><button type="button" data-fw-open="${link.id}">Open Firewall Investigation</button></div></article>`).join('');
  const evidences = (window.__stateEvidence?.maliciousIps || []).join(', ');
  document.getElementById('opsPanel').innerHTML = `
    <article class="malware-card">
      <div><strong>🧪 Machine Forensics</strong></div>
      <div class="threat">Process analysis is optional and runs only when you open it for the current machine.</div>
      <div class="malware-actions"><button type="button" data-open-process-lab="${context.host.id}">Investigate ${context.host.id} processes</button></div>
    </article>
    <article class="malware-card">
      <div><strong>🔥 Firewall Investigation</strong></div>
      <div class="threat">Click a map firewall knob or open a related link below to solve route/log puzzle before blocking traffic.</div>
      <div class="threat">Evidence hints for firewall/fileserver actions: ${evidences || 'No IOC IPs collected yet.'}</div>
      <div class="malware-panel">${cards || '<p class="threat">No nearby links for this machine.</p>'}</div>
    </article>
  `;
}

function getFirewallCase(linkId) {
  const preset = FIREWALL_CASES[linkId] || FIREWALL_CASES['provider-corp'];
  if (!firewallLabState[linkId]) {
    firewallLabState[linkId] = { routesChecked: false, logsChecked: false, inspectedIp: null, picked: null };
  }
  return { ...preset, state: firewallLabState[linkId] };
}

function openFirewallLab(linkId, onFirewallChange) {
  const modal = document.getElementById('analysisModal');
  const body = document.getElementById('analysisBody');
  const lab = getFirewallCase(linkId);
  const suspectButtons = lab.suspects.map((s) => `<button type="button" data-fw-suspect-link="${linkId}" data-fw-suspect-ip="${s.ip}">${s.ip}</button>`).join('');
  const actionButtons = !lab.state.inspectedIp
    ? '<em>Inspect at least one IP before changing policy.</em>'
    : `<button type="button" data-fw-action-link="${linkId}" data-fw-action-mode="monitor">MONITOR</button>
       <button type="button" data-fw-action-link="${linkId}" data-fw-action-mode="allow">ALLOW</button>
       <button type="button" data-fw-action-link="${linkId}" data-fw-action-mode="block">BLOCK ${lab.state.inspectedIp}</button>`;

  modal.classList.remove('hidden');
  body.innerHTML = `
    <strong>Firewall Lab: ${linkId}</strong>
    <p>${lab.routePrompt}</p>
    <div class="malware-actions"><button type="button" data-fw-puzzle="${linkId}" data-fw-step="routes">1) Investigate route mess</button></div>
    ${lab.state.routesChecked ? `<p class="threat">✅ Route puzzle solved: ${lab.clues[0]}</p>` : ''}
    <p>${lab.logPrompt}</p>
    <div class="malware-actions"><button type="button" data-fw-puzzle="${linkId}" data-fw-step="logs">2) Parse huge log</button></div>
    ${lab.state.logsChecked ? `<p class="threat">✅ Log clue: ${lab.clues[1]}</p>` : ''}
    <p><strong>3) Investigate traffic suspects:</strong></p>
    <div class="malware-actions">${suspectButtons}</div>
    ${lab.state.picked ? `<p class="threat">${lab.state.picked}</p>` : ''}
    <p><strong>4) Apply firewall policy:</strong></p>
    <div class="malware-actions">${actionButtons}</div>
    <p class="threat">Goal: recover safe routes and block only confirmed malicious activity.</p>
  `;
  if (onFirewallChange) window.__fwChange = onFirewallChange;
}

function runFirewallPuzzleStep(linkId, step) {
  const lab = getFirewallCase(linkId);
  if (step === 'routes') lab.state.routesChecked = true;
  if (step === 'logs') lab.state.logsChecked = true;
  openFirewallLab(linkId, window.__fwChange);
}

function inspectFirewallSuspect(linkId, ip) {
  const lab = getFirewallCase(linkId);
  const candidate = lab.suspects.find((s) => s.ip === ip);
  lab.state.inspectedIp = ip;
  lab.state.picked = candidate?.type === 'malicious'
    ? `🚨 ${ip} looks malicious: ${candidate.note}`
    : `ℹ️ ${ip} looks normal: ${candidate?.note || 'no anomaly found'}`;
  openFirewallLab(linkId, window.__fwChange);
}

function openProcessLab(hostId, onProcessAction) {
  const modal = document.getElementById('analysisModal');
  const body = document.getElementById('analysisBody');
  const scan = window.__getProcessScan?.(hostId);
  if (!scan) return;
  const rows = scan.processes.map((p) => `
    <tr>
      <td>${p.name}</td>
      <td>${p.cpu || '-'}</td>
      <td>${p.memory || '-'}</td>
      <td>${p.network || '-'}</td>
      <td><button type="button" data-proc-host="${hostId}" data-proc-name="${p.name}" data-proc-action="analyze" data-proc-verdict="${p.verdict}">Investigate</button></td>
      <td><button type="button" data-proc-host="${hostId}" data-proc-name="${p.name}" data-proc-action="block" data-proc-verdict="${p.verdict}">Stop</button></td>
    </tr>
  `).join('');
  modal.classList.remove('hidden');
  body.innerHTML = `
    <strong>Process List - ${hostId}</strong>
    <p class="machine-brief">${scan.prompt}</p>
    <table class="proc-table"><thead><tr><th>Name</th><th>CPU</th><th>Memory</th><th>Network</th><th></th><th></th></tr></thead><tbody>${rows}</tbody></table>
  `;
  if (onProcessAction) window.__procAction = onProcessAction;
}

function openMachineModal(hostId, nodeId) {
  const modal = document.getElementById('analysisModal');
  const body = document.getElementById('analysisBody');
  const host = window.__machineMeta?.[hostId] || { id: hostId, role: 'machine', description: '' };
  const customActions = MACHINE_ACTIONS[hostId] || [
    { id: 'trace-route', label: 'Investigate network route', command: 'tracert 10.10.66.77' },
    { id: 'aggressive-scan', label: 'Aggressive scan (high risk)', command: `nmap -p 1-65535 -T 4 ${hostId}` }
  ];
  const actionButtons = customActions.map((a) => `<button type="button" data-machine-host="${host.id}" data-machine-op="${a.id}" title="${escapeAttr(a.command)}">${a.label}</button>`).join('');
  const actionCommands = customActions.map((a) => `<code>${a.command}</code>`).join('');
  modal.classList.remove('hidden');
  body.innerHTML = `
    <strong>${host.id}</strong>
    <p class="machine-brief"><strong>Purpose:</strong> ${host.role}</p>
    <p class="threat">${host.description || 'Machine information unavailable.'}</p>
    <p><strong>Actions</strong></p>
    <div class="malware-actions">
      <button type="button" data-machine-jump="${nodeId}">Open machine workspace</button>
      <button type="button" data-open-process-lab="${host.id}">Process investigation</button>
      ${actionButtons}
    </div>
    <div class="proc-cmds">${actionCommands}</div>
  `;
}

function renderServiceWindows(network) {
  const apps = APP_WINDOWS[network] || [];
  document.getElementById('serviceApps').innerHTML = apps.map((app) => `<button type="button" class="app-btn" data-app-open="${app.title}" data-app-hint="${escapeAttr(app.hint)}" data-app-body="${escapeAttr(app.body)}">Open ${app.title}</button>`).join('') || '<p class="threat">No network app previews here.</p>';
}

function renderGuidancePanel(checklist) {
  document.getElementById('guidancePanel').innerHTML = checklist.map((item) => `<li>${item}</li>`).join('');
}

function runMachineOperation(hostId, operation, onMachineOperation) {
  if (!onMachineOperation) return;
  const modal = document.getElementById('analysisModal');
  const body = document.getElementById('analysisBody');
  const result = onMachineOperation(hostId, operation);
  modal.classList.remove('hidden');
  body.innerHTML = `
    <strong>Machine operation result</strong>
    <p><code>${result?.command || 'n/a'}</code></p>
    <p>${result?.text || 'No result'}</p>
  `;
}


async function runTransition(text, fn, min = 1000, max = 2000) {
  const modal = document.getElementById('analysisModal');
  const body = document.getElementById('analysisBody');
  modal.classList.remove('hidden');
  body.innerHTML = `<strong>${text}</strong>`;
  const wait = min + Math.floor(Math.random() * (max - min + 1));
  await new Promise((r) => setTimeout(r, wait));
  fn();
  modal.classList.add('hidden');
}

async function runProcessAction(onProcessAction, hostId, processName, action, verdict = 'benign') {
  const runner = onProcessAction || window.__procAction;
  if (!runner) return null;
  const modal = document.getElementById('analysisModal');
  const body = document.getElementById('analysisBody');
  if (action !== 'analyze') {
    const stopped = runner(hostId, processName, action);
    body.innerHTML = `<strong>Process stop result</strong><p>${stopped?.impact || `${processName} stopped.`}</p>`;
    return stopped;
  }
  modal.classList.remove('hidden');
  const [min, max] = verdict === 'suspicious' ? [5000, 10000] : verdict === 'critical' ? [5000, 7000] : [2000, 2500];
  body.innerHTML = `<strong>Investigating ${processName} on ${hostId} ...</strong><br/>Expected: ${Math.round(min / 1000)}-${Math.round(max / 1000)} sec`;
  const wait = min + Math.floor(Math.random() * (max - min + 1));
  await new Promise((resolve) => setTimeout(resolve, wait));
  const result = runner(hostId, processName, action);
  const evidenceText = result?.evidence
    ? `<p>Gained evidences: ${result.evidence.maliciousIp || 'unknown IP'} ${result.evidence.executionPath ? `<br/>Execution path: ${result.evidence.executionPath}` : ''}</p>`
    : '<p>Nothing interesting here...</p>';
  body.innerHTML = `<strong>${result ? `${result.name}: ${result.verdict}` : 'No data'}</strong>${evidenceText}`;
  return result;
}

function openSiteModal(title, hint, body) {
  const modal = document.getElementById('analysisModal');
  const text = document.getElementById('analysisBody');
  modal.classList.remove('hidden');
  text.innerHTML = `<strong>${title}</strong><br/><em>${hint}</em><div class="site-preview">${body}</div>`;
}

function closeProcessModal() {
  document.getElementById('analysisModal').classList.add('hidden');
}

function renderCommand(text) {
  document.getElementById('commandBuilder').textContent = text.length > 140 ? `${text.slice(0, 137)}...` : text;
}

function renderLeaderboard() {
  const board = loadLeaderboard();
  document.getElementById('leaderboard').innerHTML = board.map((e) => `<li>${e.name} — ${e.score} (${e.timeLeftSec}s)</li>`).join('');
}

function renderDevMap(game, show) {
  const el = document.getElementById('devMap');
  if (!show) return el.classList.add('hidden');
  el.classList.remove('hidden');
  const options = game.getAvailableOptions();
  el.innerHTML = `<div><strong>Current:</strong> ${game.state.nodeId}</div><div><strong>Neighbors:</strong> ${options.map((o) => o.next).join(', ')}</div>`;
}

function escapeAttr(value = '') {
  return value.replace(/"/g, '&quot;');
}

function shorten(text, max) {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}
