import { getScoreBreakdown } from './scoring.js';

const NETWORKS = ['provider', 'corp', 'ot', 'drone'];
const FIREWALL_LINKS = [
  { id: 'provider-corp', a: 'provider', b: 'corp', service: 'HTTPS/DNS feed' },
  { id: 'corp-ot', a: 'corp', b: 'ot', service: 'SMB historian sync' },
  { id: 'corp-drone', a: 'corp', b: 'drone', service: 'UAV mission package' },
  { id: 'provider-drone', a: 'provider', b: 'drone', service: 'UAV live stream relay' }
];

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
      firewall: Object.fromEntries(FIREWALL_LINKS.map((l) => [l.id, 'allow'])),
      flags: { stoppedDetonation: false },
      penaltyArmed: false,
      outagePenaltyTicks: 0,
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

  getFirewallLinks() {
    return FIREWALL_LINKS.map((link) => ({ ...link, status: this.state.firewall[link.id] || 'allow' }));
  }

  setFirewallRule(linkId, status) {
    const link = FIREWALL_LINKS.find((l) => l.id === linkId);
    if (!link || !['allow', 'monitor', 'block'].includes(status)) return;
    this.state.firewall[linkId] = status;
    if (status === 'block') {
      this.state.score -= 8;
      this.state.effectMessage = `Firewall blocked ${link.service} (${link.a} ↔ ${link.b}). Dependent apps may fail.`;
    } else if (status === 'monitor') {
      this.state.score += 2;
      this.state.effectMessage = `Firewall monitoring enabled for ${link.service} (${link.a} ↔ ${link.b}). Traffic stays up while SOC watches for indicators.`;
    } else {
      this.state.score += 4;
      this.state.effectMessage = `Firewall restored ${link.service} (${link.a} ↔ ${link.b}).`;
    }
  }

  getProcessScan(hostId) {
    const lower = hostId.toLowerCase();
    if (lower.includes('corp_hr')) {
      return {
        prompt: 'HR workstation has 140+ background tasks. Is that normal HR software noise or hidden malware?',
        commands: ['Get-Process | Sort-Object CPU -Descending | Select -First 25', 'Get-ScheduledTask | ? TaskName -match "update|sync|hr"'],
        processes: [
          { name: 'excel.exe', verdict: 'benign', functions: ['payroll macro workbook'] },
          { name: 'powershell.exe', verdict: 'suspicious', functions: ['encoded startup command', 'credential scraping script'] },
          { name: 'teams.exe', verdict: 'benign', functions: ['chat and meetings'] }
        ]
      };
    }
    if (lower.includes('corp_dc')) {
      return {
        prompt: 'Domain controller process tree has an odd calc.exe launch under service context. Legit admin prank or compromise?',
        commands: ['Get-WinEvent -LogName Security -MaxEvents 200 | ? Message -match "calc.exe|service"', 'Get-CimInstance Win32_Process | Select Name,ParentProcessId,CommandLine'],
        processes: [
          { name: 'lsass.exe', verdict: 'benign', functions: ['authentication authority process'] },
          { name: 'calc.exe', verdict: 'suspicious', functions: ['unexpected GUI binary in server session', 'possible LOLBIN launch marker'] },
          { name: 'dns.exe', verdict: 'benign', functions: ['domain DNS service'] }
        ]
      };
    }
    if (lower.includes('corp_fs') || lower.includes('provider')) {
      return {
        prompt: 'so many powershell.exe process, is that a new company policy?',
        commands: ['Get-Process | Sort-Object CPU -Descending | Select -First 20', 'Get-CimInstance Win32_Process | Select Name,ProcessId,CommandLine'],
        processes: [
          { name: 'powershell.exe', verdict: 'suspicious', functions: ['download cradle', 'credential dump attempt', 'encoded command loader'] },
          { name: 'svchost.exe', verdict: 'benign', functions: ['service host group: netsvcs'] },
          { name: 'uav.exe', verdict: hostId.includes('drone') ? 'critical' : 'benign', functions: ['flight control uplink', 'telemetry marshaling'] }
        ]
      };
    }
    if (lower.includes('drone') || lower.includes('plan')) {
      return {
        prompt: 'Telemetry jitter detected while UAV mission package is open.',
        commands: ['ps aux --sort=-%cpu | head -20', 'ss -plant | grep ESTAB'],
        processes: [
          { name: 'uav.exe', verdict: 'critical', functions: ['flight stability controller', 'return-to-base safety handler'] },
          { name: 'reverse_tunnel', verdict: 'suspicious', functions: ['reverse shell', 'beacon channel to C2'] },
          { name: 'ffmpeg', verdict: 'benign', functions: ['video transcoding'] }
        ]
      };
    }
    if (lower.includes('ot')) {
      return {
        prompt: 'PLC command queue includes unusual writes.',
        commands: ['modbus read 10.77.4.20:502 holding 40001 10', 'modbus write-test --dry-run --address 40110 --value 0'],
        processes: [
          { name: 'scada-syncd', verdict: 'critical', functions: ['setpoint replication', 'safety trip thresholds'] },
          { name: 'plc_writer', verdict: 'suspicious', functions: ['unauthorized coil writes', 'breaker state manipulation'] },
          { name: 'historiand', verdict: 'benign', functions: ['trend archiving'] }
        ]
      };
    }
    return {
      prompt: 'Process baseline collected.',
      commands: ['Get-Process', 'ps aux'],
      processes: []
    };
  }

  analyzeProcess(hostId, processName) {
    const scan = this.getProcessScan(hostId);
    const proc = scan.processes.find((p) => p.name === processName);
    if (!proc) return null;
    if (proc.verdict === 'suspicious') {
      this.state.score += 22;
      this.revealNextKillChainStage();
    }
    return proc;
  }

  blockProcess(hostId, processName) {
    const proc = this.getProcessScan(hostId).processes.find((p) => p.name === processName);
    if (!proc) return;
    if (proc.verdict === 'critical') {
      this.state.score -= 70;
      this.state.noise = Math.min(10, this.state.noise + 2);
      if (processName === 'uav.exe') this.state.access.drone = false;
      if (hostId.includes('ot')) this.state.access.ot = false;
      this.state.effectMessage = `Critical process ${processName} blocked on ${hostId}: service impact propagated across connected networks.`;
      return;
    }
    this.state.score += proc.verdict === 'suspicious' ? 26 : -6;
    this.state.effectMessage = proc.verdict === 'suspicious'
      ? `Blocked malicious process ${processName} on ${hostId}.`
      : `${processName} looked legitimate; review before blocking next time.`;
  }


  getRemediationChecklist() {
    const checks = [];
    const blocked = FIREWALL_LINKS.filter((l) => this.state.firewall[l.id] === 'block');
    const monitored = FIREWALL_LINKS.filter((l) => this.state.firewall[l.id] === 'monitor');
    if (blocked.length) checks.push(`Restore required firewall channels: ${blocked.map((b) => b.id).join(', ')}.`);
    else if (monitored.length) checks.push(`Firewall channels monitored without outage: ${monitored.map((m) => m.id).join(', ')}.`);
    else checks.push('Firewall channels healthy: keep only malicious flows blocked.');

    const down = NETWORKS.filter((n) => !this.state.access[n]);
    if (down.length) checks.push(`Network impact detected on: ${down.join(', ')}. Rectify service/process disruptions.`);
    else checks.push('All subnets reachable from SOC.');

    if (!this.state.flags.ransomwareContained) checks.push('Ransomware not contained yet: protect finance/shared files first.');
    else checks.push('Ransomware containment confirmed.');

    if (this.state.killChain.revealed.length < 5) checks.push('Kill-chain evidence incomplete: continue process/log/file analysis.');
    else checks.push('Kill-chain map is becoming actionable for final containment.');

    return checks;
  }

  revealNextKillChainStage() {
    const next = this.state.killChain.stages.find((stage) => !this.state.killChain.revealed.includes(stage));
    if (next) this.state.killChain.revealed.push(next);
  }

  tick(seconds = 1) {
    if (this.state.sessionEnded) return;
    this.consumeTime(seconds);
    this.applyOutagePenalties();
  }

  applyOutagePenalties() {
    const elapsed = 600 - this.state.timeLeftSec;
    if (elapsed >= 120) this.state.penaltyArmed = true;
    if (!this.state.penaltyArmed) return;
    const blockedLinks = FIREWALL_LINKS.filter((l) => this.state.firewall[l.id] === 'block').length;
    const lockedNetworks = NETWORKS.filter((n) => !this.state.access[n]).length;
    const outageWeight = blockedLinks + lockedNetworks;
    if (outageWeight <= 0) return;
    this.state.outagePenaltyTicks += 1;
    if (this.state.outagePenaltyTicks % 5 === 0) {
      this.state.score -= outageWeight * 2;
      this.state.effectMessage = `Public apps unavailable for users: outage penalties applied (${outageWeight} impacted channels).`;
    }
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
