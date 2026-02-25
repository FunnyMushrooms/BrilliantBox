import { loadLeaderboard } from './storage.js';

const NETWORK_LABELS = {
  provider: 'Provider Network',
  corp: 'Corporate IT',
  ot: 'ICS / Power Plant OT',
  drone: 'DroneOps / Secure Lab'
};

export function bindUI({ onChoose, onReplay, onExport, onToggleMap }) {
  document.getElementById('newSeedBtn').onclick = () => onReplay('new');
  document.getElementById('sameSeedBtn').onclick = () => onReplay('same');
  document.getElementById('exportBtn').onclick = onExport;
  document.getElementById('toggleMapBtn').onclick = onToggleMap;
  document.addEventListener('keydown', (e) => {
    if (e.key >= '1' && e.key <= '9') onChoose(Number(e.key) - 1);
  });
}

export function render(game, scenario, showMap = false) {
  const state = game.state;
  const node = scenario.nodes[state.nodeId];
  document.getElementById('seedValue').textContent = game.seed;
  document.getElementById('timerValue').textContent = `${String(Math.floor(state.timeLeftSec / 60)).padStart(2, '0')}:${String(state.timeLeftSec % 60).padStart(2, '0')}`;
  document.getElementById('scoreValue').textContent = state.score;
  meter('noise', state.noise);
  meter('ot', state.otRisk);
  document.getElementById('nodeTitle').textContent = node.title;
  document.getElementById('nodeText').textContent = node.text;
  document.getElementById('effectsText').textContent = state.effectMessage;

  renderChoices(game.getAvailableOptions());
  renderNetworkMap(state.access);
  renderInventory(state);
  renderCommand(node.commandPreview || 'Select a network action and tool profile.');
  renderLeaderboard();
  renderDevMap(game, scenario, showMap);

  if (state.sessionEnded) {
    document.getElementById('effectsText').textContent = `Session ended: ${state.ending}. Hosts found: ${state.foundHosts.length}.`;
  }
}

function meter(prefix, v) {
  document.getElementById(`${prefix}Meter`).value = v;
  document.getElementById(`${prefix}Value`).textContent = `${v}/10`;
}

function renderChoices(options) {
  const c = document.getElementById('choices');
  c.innerHTML = '';
  options.forEach((opt, i) => {
    const b = document.createElement('button');
    b.className = 'choice-btn';
    b.textContent = `[${i + 1}] ${opt.label} (-${opt.timeCostSec || 0}s)`;
    b.onclick = () => window.__choose(i);
    c.appendChild(b);
  });
}

function renderNetworkMap(access) {
  const el = document.getElementById('networkMap');
  el.innerHTML = '';
  Object.entries(NETWORK_LABELS).forEach(([key, label]) => {
    const tile = document.createElement('div');
    tile.className = `network-tile ${access[key] ? '' : 'locked'}`;
    tile.textContent = `${label} ${access[key] ? '🟢' : '🔒'}`;
    el.appendChild(tile);
  });
}

function renderInventory(state) {
  document.getElementById('inventory').innerHTML = `
    <p><strong>Items:</strong> ${state.inventory.join(', ') || 'None'}</p>
    <p><strong>Found Hosts (${state.foundHosts.length}):</strong> ${state.foundHosts.join(', ') || 'None'}</p>
  `;
}

function renderCommand(text) {
  const t = text.length > 80 ? `${text.slice(0, 77)}...` : text;
  document.getElementById('commandBuilder').textContent = t;
}

function renderLeaderboard() {
  const board = loadLeaderboard();
  const el = document.getElementById('leaderboard');
  el.innerHTML = board.map(e => `<li>${e.name} — ${e.score} (${e.timeLeftSec}s)</li>`).join('');
}

function renderDevMap(game, scenario, show) {
  const el = document.getElementById('devMap');
  if (!show) { el.classList.add('hidden'); return; }
  el.classList.remove('hidden');
  const options = game.getAvailableOptions();
  el.innerHTML = `<div><strong>Current:</strong> ${game.state.nodeId}</div><div><strong>Neighbors:</strong> ${options.map(o => o.next).join(', ')}</div>`;
}
