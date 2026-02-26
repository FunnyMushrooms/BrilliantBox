import { GameEngine } from './engine.js';
import { loadScenario, applySeed, validateScenarioShape } from './scenarioLoader.js';
import { bindUI, render } from './ui.js';
import { saveLeaderboard, saveSession } from './storage.js';

let context;
let showMap = false;
let difficulty = 'expert';
let timerHandle;

function randomSeed() {
  return `seed-${Math.random().toString(36).slice(2, 10)}`;
}

async function start(mode = 'new') {
  const loaded = await loadScenario();
  validateScenarioShape(loaded.scenario);
  const seed = mode === 'same' && context?.seed ? context.seed : randomSeed();
  const seeded = applySeed(loaded.hostPool, seed);
  seeded.hostMap = loaded.hostPool.hosts;
  const game = new GameEngine({ scenario: loaded.scenario, seededHosts: seeded, seed });
  context = { ...loaded, game, seed };

  window.__choose = (idx) => {
    game.applyOption(idx);
    if (game.state.sessionEnded) finalizeRun();
    rerender();
  };

  window.__jumpNode = (nodeId) => {
    if (game.state.sessionEnded) return;
    if (!context.scenario.nodes[nodeId]) return;
    game.state.nodeId = nodeId;
    game.state.effectMessage = `Opened machine view: ${nodeId}`;
    rerender();
  };

  window.__getProcessScan = (hostId) => game.getProcessScan(hostId);

  bindUI({
    onChoose: (idx) => window.__choose(idx),
    onReplay: (m) => start(m),
    onExport: exportReport,
    onToggleMap: () => { showMap = !showMap; rerender(); },
    onDifficultyChange: (value) => { difficulty = value; rerender(); },
    onMalwareAction: (hostId, action) => {
      game.interactWithMalware(hostId, action);
      if (game.state.sessionEnded) finalizeRun();
      rerender();
    },
    onJumpNode: (nodeId) => window.__jumpNode(nodeId),
    onFirewallChange: (linkId, status) => {
      game.setFirewallRule(linkId, status);
      rerender();
    },
    onProcessAction: (hostId, processName, action) => {
      if (action === 'analyze') {
        const result = game.analyzeProcess(hostId, processName);
        rerender();
        return result;
      }
      game.blockProcess(hostId, processName);
      if (game.state.sessionEnded) finalizeRun();
      rerender();
      return null;
    }
  });

  startTimer();
  rerender();
}

function startTimer() {
  if (timerHandle) clearInterval(timerHandle);
  timerHandle = setInterval(() => {
    if (!context?.game || context.game.state.sessionEnded) return;
    context.game.tick(1);
    if (context.game.state.sessionEnded) finalizeRun();
    rerender();
  }, 1000);
}

function rerender() {
  render(context.game, context.scenario, showMap, difficulty);
  saveSession(context.game.state);
}

async function finalizeRun() {
  const name = `Agent-${new Date().getMinutes()}`;
  const entry = { name, score: context.game.state.score, timeLeftSec: context.game.state.timeLeftSec, seed: context.seed };
  saveLeaderboard(entry);
  if (context.config?.remoteLeaderboard?.enabled) {
    try {
      await fetch(context.config.remoteLeaderboard.endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(entry)
      });
    } catch (_) { /* optional remote */ }
  }
}

function exportReport() {
  const blob = new Blob([JSON.stringify(context.game.exportReport(), null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `incident-report-${context.seed}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

start();
