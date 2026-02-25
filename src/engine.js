import { getScoreBreakdown } from './scoring.js';

const NETWORKS = ['provider', 'corp', 'ot', 'drone'];

export class GameEngine {
  constructor({ scenario, seededHosts, seed }) {
    this.scenario = scenario;
    this.seed = seed;
    this.seededHosts = seededHosts;
    this.timeline = [];
    this.path = [];
    this.state = this.initialState();
  }

  initialState() {
    return {
      nodeId: this.scenario.startNode,
      score: 0,
      timeLeftSec: 600,
      noise: 0,
      otRisk: 0,
      access: Object.fromEntries(NETWORKS.map(n => [n, true])),
      inventory: [],
      foundHosts: [],
      unlockedActions: [],
      killChain: {
        stages: ['recon', 'weaponization', 'delivery', 'exploitation', 'installation', 'command-and-control', 'actions-on-objectives'],
        revealed: []
      },
      malwareSightings: {},
      flags: { stoppedDetonation: false },
      sessionEnded: false,
      ending: null,
      effectMessage: ''
    };
  }

  getNode(id = this.state.nodeId) { return this.scenario.nodes[id]; }

  getAvailableOptions() {
    const node = this.getNode();
    return (node.options || []).filter(opt => this.optionAllowed(opt));
  }

  optionAllowed(opt) {
    const c = opt.conditions || {};
    if (c.requiredItems && !c.requiredItems.every(i => this.state.inventory.includes(i))) return false;
    if (c.requiredFlags && !Object.entries(c.requiredFlags).every(([k, v]) => this.state.flags[k] === v)) return false;
    if (c.networkAccessRequired && !this.state.access[c.networkAccessRequired]) return false;
    if (typeof c.maxNoise === 'number' && this.state.noise > c.maxNoise) return false;
    if (typeof c.minNoise === 'number' && this.state.noise < c.minNoise) return false;
    return true;
  }

  applyOption(index) {
    if (this.state.sessionEnded) return;
    const option = this.getAvailableOptions()[index];
    if (!option) return;
    const effects = option.effects || {};
    this.state.score += effects.scoreDelta || 0;
    this.state.noise = Math.min(10, Math.max(0, this.state.noise + (effects.noiseDelta || 0)));
    this.state.otRisk = Math.min(10, Math.max(0, this.state.otRisk + (effects.otRiskDelta || 0)));

    for (const [k, v] of Object.entries(effects.setFlags || {})) this.state.flags[k] = v;
    for (const item of effects.addItems || []) if (!this.state.inventory.includes(item)) this.state.inventory.push(item);
    for (const action of effects.unlockActions || []) {
      if (!this.state.unlockedActions.includes(action)) this.state.unlockedActions.push(action);
      if (this.state.killChain.stages.includes(action) && !this.state.killChain.revealed.includes(action)) {
        this.state.killChain.revealed.push(action);
      }
    }
    if (effects.lockoutNetwork) this.state.access[effects.lockoutNetwork] = false;

    for (const hostId of effects.addFoundHosts || []) this.discoverHost(hostId);

    if (effects.rollFromNetwork) this.rollHostDiscovery(effects.rollFromNetwork, effects.maxFind || 2);

    this.state.effectMessage = option.effectText || '';
    this.path.push({ nodeId: this.state.nodeId, option: option.label, t: 600 - this.state.timeLeftSec });
    this.timeline.push({ t: 600 - this.state.timeLeftSec, noise: this.state.noise, otRisk: this.state.otRisk, score: this.state.score });

    if (this.state.noise >= 9 && effects.network) {
      this.state.access[effects.network] = false;
      this.state.effectMessage += ' Security systems throttled that network.';
    }
    if (this.state.otRisk >= 10) {
      this.state.score -= 120;
      this.state.effectMessage += ' OT process upset penalty applied.';
    }

    this.state.nodeId = option.next;
    this.resolveAutoNode();
  }

  rollHostDiscovery(network, maxFind) {
    const matches = this.seededHosts.hostMap.filter(h => h.network === network && this.seededHosts.infected.has(h.id));
    const notFound = matches.filter(h => !this.state.foundHosts.includes(h.id));
    const pick = notFound.slice(0, maxFind);
    pick.forEach(h => this.discoverHost(h.id));
  }

  discoverHost(hostId) {
    if (this.state.foundHosts.includes(hostId)) return;
    if (this.seededHosts.armedDecoys.has(hostId)) {
      this.state.noise = Math.min(10, this.state.noise + 2);
      this.state.effectMessage += ` Decoy ${hostId} tripped.`;
      return;
    }
    this.state.foundHosts.push(hostId);
    if (!this.state.malwareSightings[hostId]) {
      this.state.malwareSightings[hostId] = {
        status: 'active',
        threat: this.inferThreatType(hostId)
      };
    }
    this.state.score += 90;
    if (!this.state.inventory.includes('ioc-template')) this.state.inventory.push('ioc-template');
  }

  inferThreatType(hostId) {
    if (hostId.includes('dc') || hostId.includes('fs')) return 'credential-stealer';
    if (hostId.includes('ot')) return 'process-killer';
    if (hostId.includes('drone')) return 'build-backdoor';
    return 'loader';
  }

  interactWithMalware(hostId, action) {
    const sighting = this.state.malwareSightings[hostId];
    if (!sighting || sighting.status === 'eradicated') return;

    if (action === 'analyze') {
      this.state.score += 18;
      this.revealNextKillChainStage();
      this.state.effectMessage = `Reverse engineering notes updated for ${hostId}.`;
      return;
    }

    if (action === 'quarantine') {
      sighting.status = 'contained';
      this.state.score += 25;
      this.state.effectMessage = `${hostId} isolated. Malware can no longer spread from this host.`;
      return;
    }

    if (action === 'eradicate') {
      if (sighting.status !== 'contained') {
        this.state.noise = Math.min(10, this.state.noise + 1);
        this.state.score -= 8;
        this.state.effectMessage = `Rushed removal on ${hostId} left noisy traces. Try containing first.`;
        return;
      }
      sighting.status = 'eradicated';
      this.state.score += 35;
      this.revealNextKillChainStage();
      this.state.effectMessage = `Malware eradicated on ${hostId}.`;
    }
  }

  revealNextKillChainStage() {
    const next = this.state.killChain.stages.find((stage) => !this.state.killChain.revealed.includes(stage));
    if (next) this.state.killChain.revealed.push(next);
  }

  tick(seconds = 1) {
    if (this.state.sessionEnded) return;
    this.consumeTime(seconds);
  }

  consumeTime(seconds) {
    this.state.timeLeftSec = Math.max(0, this.state.timeLeftSec - seconds);
    if (this.state.timeLeftSec <= 0) this.endSession('timeout');
  }

  resolveAutoNode() {
    const node = this.getNode();
    if (!node) return;
    if (node.type === 'win') this.endSession('win');
    if (node.type === 'end') this.endSession('end');
    if (this.state.foundHosts.length >= 12 && this.state.flags.stoppedDetonation) this.endSession('perfect');
    else if (this.state.foundHosts.length >= 8 && node.id === 'final_assess') this.endSession('win');
  }

  endSession(ending) {
    this.state.sessionEnded = true;
    this.state.ending = ending;
    this.state.breakdown = getScoreBreakdown(this.state);
    this.state.score = this.state.breakdown.total;
  }

  exportReport() {
    return {
      seed: this.seed,
      ending: this.state.ending,
      score: this.state.score,
      meters: { noise: this.state.noise, otRisk: this.state.otRisk, timeLeftSec: this.state.timeLeftSec },
      foundHosts: this.state.foundHosts,
      inventory: this.state.inventory,
      path: this.path,
      timeline: this.timeline,
      malwareSightings: this.state.malwareSightings,
      breakdown: this.state.breakdown || getScoreBreakdown(this.state)
    };
  }
}
