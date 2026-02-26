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

export function bindUI({ onChoose, onReplay, onExport, onToggleMap, onDifficultyChange, onMalwareAction, onJumpNode, onFirewallChange, onProcessAction }) {
  document.getElementById('newSeedBtn').onclick = () => onReplay('new');
  document.getElementById('sameSeedBtn').onclick = () => onReplay('same');
  document.getElementById('exportBtn').onclick = onExport;
  document.getElementById('toggleMapBtn').onclick = onToggleMap;
  document.getElementById('difficultyMode').onchange = (e) => onDifficultyChange(e.target.value);

  document.addEventListener('click', async (e) => {
    const malwareBtn = e.target.closest('[data-malware-host]');
    if (malwareBtn) return onMalwareAction(malwareBtn.dataset.malwareHost, malwareBtn.dataset.action);

    const jump = e.target.closest('[data-jump-node]');
    if (jump) return runTransition(`Switching to ${jump.dataset.jumpNode} ...`, () => onJumpNode(jump.dataset.jumpNode));

    const fw = e.target.closest('[data-fw-link]');
    if (fw) {
      await runTransition('Applying firewall policy change ...', () => onFirewallChange(fw.dataset.fwLink, fw.dataset.fwAction), 1200, 2000);
      return;
    }

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
  renderNetworkMap(state.access, firewallLinks);
  renderKillChain(state.killChain || { stages: [], revealed: [] });
  renderInventory(state, game.seededHosts?.hostMap || []);
  renderMalwarePanel(state.malwareSightings || {}, game.seededHosts?.hostMap || []);
  renderFirewallPanel(firewallLinks);
  renderProcessLab(context, game.getProcessScan(context.host.id), firewallLinks, difficulty);
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
  `;
}

function renderChoices(node, options, context, difficulty) {
  const c = document.getElementById('choices');
  c.innerHTML = '';

  if (node.id === 'start' || node.type === 'hub') {
    c.innerHTML = '<div class="choice-hint">🗺️ Use the visual network map (left) to open machines directly. No text-only pivot required.</div>';
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

function renderNetworkMap(access, links) {
  const el = document.getElementById('networkMap');
  const linkById = Object.fromEntries(links.map((l) => [l.id, l]));

  const machine = (x, y, nodeId, icon, label) => `
    <g class="map-machine" data-jump-node="${nodeId}" transform="translate(${x},${y})">
      <rect width="56" height="44" rx="10"></rect>
      <text x="28" y="18" text-anchor="middle" font-size="16">${icon}</text>
      <text x="28" y="34" text-anchor="middle" font-size="7">${label}</text>
    </g>`;

  const fwKnob = (id, x, y) => {
    const blocked = linkById[id]?.status === 'block';
    return `<g class="fw-knob ${blocked ? 'block' : 'allow'}" data-fw-link="${id}" data-fw-action="${blocked ? 'allow' : 'block'}" transform="translate(${x},${y})">
      <circle r="11"></circle>
      <text y="3" text-anchor="middle" font-size="11">${blocked ? '⛔' : '🟢'}</text>
    </g>`;
  };

  const status = (n) => !access[n] ? '🔒' : '🟢';

  el.innerHTML = `<svg viewBox="0 0 760 470" class="subnet-svg full-map" role="img" aria-label="Interactive four-network topology">
    <defs><linearGradient id="linegrad" x1="0" x2="1"><stop offset="0" stop-color="#7cd7ff"/><stop offset="1" stop-color="#d0a4ff"/></linearGradient></defs>

    <rect x="338" y="188" width="84" height="72" rx="12" class="soc-core" data-jump-node="final_assess"></rect>
    <text x="380" y="214" text-anchor="middle" font-size="20">🛡️</text>
    <text x="380" y="236" text-anchor="middle" font-size="10">SOC / Kill-Chain</text>

    <line x1="380" y1="188" x2="380" y2="92" class="map-link" />
    <line x1="338" y1="224" x2="188" y2="144" class="map-link" />
    <line x1="422" y1="224" x2="574" y2="144" class="map-link" />
    <line x1="380" y1="260" x2="380" y2="370" class="map-link" />

    ${fwKnob('provider-corp', 286, 145)}
    ${fwKnob('provider-drone', 477, 145)}
    ${fwKnob('corp-drone', 380, 146)}
    ${fwKnob('corp-ot', 282, 302)}

    <g transform="translate(380,74)"><circle r="44" class="segment provider"/><text y="-6" text-anchor="middle" font-size="21">🌐</text><text y="16" text-anchor="middle" font-size="10">PROVIDER ${status('provider')}</text></g>
    <g transform="translate(164,128)"><circle r="44" class="segment corp"/><text y="-6" text-anchor="middle" font-size="21">🏢</text><text y="16" text-anchor="middle" font-size="10">DOMAIN ${status('corp')}</text></g>
    <g transform="translate(596,128)"><circle r="44" class="segment drone"/><text y="-6" text-anchor="middle" font-size="21">🛰️</text><text y="16" text-anchor="middle" font-size="10">MIL/UAV ${status('drone')}</text></g>
    <g transform="translate(380,394)"><circle r="44" class="segment ot"/><text y="-6" text-anchor="middle" font-size="21">⚙️</text><text y="16" text-anchor="middle" font-size="10">ICS ${status('ot')}</text></g>

    ${machine(314, 94, 'provider_dns', '🗄️', 'DNS')}
    ${machine(380, 94, 'provider_router', '🔥', 'FW')}
    ${machine(446, 94, 'provider_proxy', '📦', 'Proxy')}

    ${machine(96, 152, 'corp_hr', '🪟', 'HR WS')}
    ${machine(162, 152, 'corp_dc', '🗄️', 'DC')}
    ${machine(228, 152, 'corp_fs', '💾', 'FileSrv')}

    ${machine(530, 152, 'drone_relay', '📡', 'Relay')}
    ${machine(596, 152, 'drone_plan', '💻', 'Planner')}
    ${machine(662, 152, 'drone_archive', '🎞️', 'Archive')}

    ${machine(314, 326, 'ot_hmi', '🧭', 'HMI')}
    ${machine(380, 326, 'ot_hist', '📈', 'Historian')}
    ${machine(446, 326, 'ot_gate', '🔌', 'Gateway')}
  </svg>`;
}

function renderKillChain(killChain) {
  const chain = document.getElementById('killChainPanel');
  chain.innerHTML = killChain.stages.map((stage, i) => {
    const unlocked = killChain.revealed.includes(stage);
    return `<li class="kill-step ${unlocked ? 'unlocked' : 'locked'}">${i + 1}. ${unlocked ? stage : 'hidden stage'}</li>`;
  }).join('');
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

function renderFirewallPanel(links) {
  document.getElementById('firewallPanel').innerHTML = links.map((link) => {
    const nextAction = link.status === 'block' ? 'allow' : 'block';
    return `<article class="firewall-card ${link.status}"><div><strong>${link.a.toUpperCase()} ↔ ${link.b.toUpperCase()}</strong></div><div class="threat">${link.service} • ${link.status}</div><div class="malware-actions"><button type="button" data-fw-link="${link.id}" data-fw-action="${nextAction}">${nextAction.toUpperCase()}</button></div></article>`;
  }).join('');
}

function renderProcessLab(context, scan, firewallLinks, difficulty) {
  const hostId = context.host.id;
  const commands = difficulty === 'easy' ? '' : `<div class="proc-cmds">${scan.commands.map((c) => `<code>${shorten(c, 86)}</code>`).join('')}</div>`;
  const rows = scan.processes.map((p) => `
    <article class="process-card ${p.verdict}">
      <div><strong>${p.name}</strong> <span class="status ${p.verdict === 'suspicious' ? 'active' : p.verdict === 'critical' ? 'contained' : 'eradicated'}">${p.verdict}</span></div>
      <div class="threat">${p.functions[0]}</div>
      <div class="malware-actions">
        <button type="button" data-proc-host="${hostId}" data-proc-name="${p.name}" data-proc-action="analyze" data-proc-verdict="${p.verdict}">Analyze</button>
        <button type="button" data-proc-host="${hostId}" data-proc-name="${p.name}" data-proc-action="block" data-proc-verdict="${p.verdict}">Block process</button>
      </div>
    </article>
  `).join('');

  const related = firewallLinks.filter((l) => l.a === context.network || l.b === context.network).map((l) => `<button type="button" data-fw-link="${l.id}" data-fw-action="${l.status === 'block' ? 'allow' : 'block'}">${l.id}: ${l.status}</button>`).join('');

  document.getElementById('processPanel').innerHTML = `
    <p class="machine-brief"><strong>Process scan:</strong> ${scan.prompt}</p>
    ${commands}
    <div class="process-list">${rows}</div>
    <p class="machine-brief"><strong>Related network channels:</strong></p>
    <div class="malware-actions">${related || '<span class="threat">No linked channels.</span>'}</div>
  `;
}

function renderServiceWindows(network) {
  const apps = APP_WINDOWS[network] || [];
  document.getElementById('serviceApps').innerHTML = apps.map((app) => `<button type="button" class="app-btn" data-app-open="${app.title}" data-app-hint="${escapeAttr(app.hint)}" data-app-body="${escapeAttr(app.body)}">Open ${app.title}</button>`).join('') || '<p class="threat">No network app previews here.</p>';
}

function renderGuidancePanel(checklist) {
  document.getElementById('guidancePanel').innerHTML = checklist.map((item) => `<li>${item}</li>`).join('');
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
  if (action !== 'analyze') return onProcessAction(hostId, processName, action);
  const modal = document.getElementById('analysisModal');
  const body = document.getElementById('analysisBody');
  modal.classList.remove('hidden');
  const [min, max] = verdict === 'suspicious' ? [5000, 10000] : verdict === 'critical' ? [5000, 7000] : [2000, 2500];
  body.innerHTML = `<strong>Analyzing ${processName} on ${hostId} ...</strong><br/>Expected: ${Math.round(min / 1000)}-${Math.round(max / 1000)} sec`;
  const wait = min + Math.floor(Math.random() * (max - min + 1));
  await new Promise((resolve) => setTimeout(resolve, wait));
  const result = onProcessAction(hostId, processName, action);
  body.textContent = result
    ? `${result.name}: ${result.verdict}. Functions: ${result.functions.join(', ')}.`
    : `No data for ${processName}.`;
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
