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
      evidence: {
        maliciousIps: [],
        executionPaths: []
      },
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
    if (lower.includes('corp-hr')) {
      return {
        prompt: 'HR workstation has 140+ background tasks. Is that normal HR software noise or hidden malware?',
        commands: ['Get-Process | Sort-Object CPU -Descending | Select -First 25', 'Get-ScheduledTask | ? TaskName -match "update|sync|hr"'],
        processes: [
          { name: 'excel.exe', verdict: 'benign', cpu: '4%', memory: '210MB', network: '1mbps', functions: ['payroll macro workbook'] },
          {
            name: 'instagram.exe',
            verdict: 'suspicious',
            cpu: '15%',
            memory: '250MB',
            network: '9mbps',
            functions: ['unexpected upload burst', 'credential scraping script'],
            evidence: { maliciousIp: '185.55.55.10', executionPath: '\\corp-fs-02\\public\\media\\instagram.exe' }
          },
          { name: 'teams.exe', verdict: 'benign', cpu: '3%', memory: '120MB', network: '2mbps', functions: ['chat and meetings'] }
        ]
      };
    }
    if (lower.includes('corp-dc')) {
      return {
        prompt: 'Domain controller process tree has an odd calc.exe launch under service context. Legit admin prank or compromise?',
        commands: ['Get-WinEvent -LogName Security -MaxEvents 200 | ? Message -match "calc.exe|service"', 'Get-CimInstance Win32_Process | Select Name,ParentProcessId,CommandLine'],
        processes: [
          { name: 'lsass.exe', verdict: 'benign', cpu: '3%', memory: '80MB', network: '0mbps', functions: ['authentication authority process'] },
          { name: 'calc.exe', verdict: 'suspicious', cpu: '9%', memory: '65MB', network: '5mbps', functions: ['unexpected GUI binary in server session', 'possible LOLBIN launch marker'], evidence: { maliciousIp: '10.91.7.77', executionPath: 'C:\\ProgramData\\Tasks\\calc.exe' } },
          { name: 'dns.exe', verdict: 'benign', cpu: '2%', memory: '56MB', network: '1mbps', functions: ['domain DNS service'] }
        ]
      };
    }
    if (lower.includes('corp-fs') || lower.includes('prov-')) {
      return {
        prompt: 'so many powershell.exe process, is that a new company policy?',
        commands: ['Get-Process | Sort-Object CPU -Descending | Select -First 20', 'Get-CimInstance Win32_Process | Select Name,ProcessId,CommandLine'],
        processes: [
          { name: 'powershell.exe', verdict: 'suspicious', cpu: '12%', memory: '170MB', network: '8mbps', functions: ['download cradle', 'credential dump attempt', 'encoded command loader'], evidence: { maliciousIp: '104.23.201.7', executionPath: 'C:\\Users\\Public\\ps-loader.ps1' } },
          { name: 'svchost.exe', verdict: 'benign', cpu: '3%', memory: '48MB', network: '1mbps', functions: ['service host group: netsvcs'] },
          { name: 'uav.exe', verdict: hostId.includes('drone') ? 'critical' : 'benign', cpu: '10%', memory: '325MB', network: '4mbps', functions: ['flight control uplink', 'telemetry marshaling'] }
        ]
      };
    }
    if (lower.includes('drone-') || lower.includes('plan')) {
      return {
        prompt: 'Telemetry jitter detected while UAV mission package is open.',
        commands: ['ps aux --sort=-%cpu | head -20', 'ss -plant | grep ESTAB'],
        processes: [
          { name: 'uav.exe', verdict: 'critical', cpu: '14%', memory: '280MB', network: '6mbps', functions: ['flight stability controller', 'return-to-base safety handler'] },
          { name: 'reverse_tunnel', verdict: 'suspicious', cpu: '11%', memory: '95MB', network: '10mbps', functions: ['reverse shell', 'beacon channel to C2'], evidence: { maliciousIp: '172.23.99.41', executionPath: '/tmp/.cache/rev_tunnel' } },
          { name: 'ffmpeg', verdict: 'benign', cpu: '7%', memory: '100MB', network: '0mbps', functions: ['video transcoding'] }
        ]
      };
    }
    if (lower.includes('ot')) {
      return {
        prompt: 'PLC command queue includes unusual writes.',
        commands: ['modbus read 10.77.4.20:502 holding 40001 10', 'modbus write-test --dry-run --address 40110 --value 0'],
        processes: [
          { name: 'scada-syncd', verdict: 'critical', cpu: '9%', memory: '190MB', network: '5mbps', functions: ['setpoint replication', 'safety trip thresholds'] },
          { name: 'plc_writer', verdict: 'suspicious', cpu: '13%', memory: '150MB', network: '7mbps', functions: ['unauthorized coil writes', 'breaker state manipulation'], evidence: { maliciousIp: '185.17.44.9', executionPath: '/opt/scada/bin/plc_writer' } },
          { name: 'historiand', verdict: 'benign', cpu: '2%', memory: '69MB', network: '0mbps', functions: ['trend archiving'] }
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
      if (proc.evidence?.maliciousIp && !this.state.evidence.maliciousIps.includes(proc.evidence.maliciousIp)) {
        this.state.evidence.maliciousIps.push(proc.evidence.maliciousIp);
        this.state.inventory.push(`ioc-ip:${proc.evidence.maliciousIp}`);
      }
      if (proc.evidence?.executionPath && !this.state.evidence.executionPaths.includes(proc.evidence.executionPath)) {
        this.state.evidence.executionPaths.push(proc.evidence.executionPath);
        this.state.inventory.push(`ioc-path:${proc.evidence.executionPath}`);
      }
      const neighbors = this.getNeighborNetworks(this.getHostNetwork(hostId) || '').join(', ');
      this.state.effectMessage = `Evidence found on ${hostId}: ${proc.evidence?.maliciousIp || 'new IOC'} ${proc.evidence?.executionPath || ''}. Check linked zones: ${neighbors || 'none'}.`;
    }
    return proc;
  }

  blockProcess(hostId, processName) {
    const proc = this.getProcessScan(hostId).processes.find((p) => p.name === processName);
    if (!proc) return;
    const network = this.getHostNetwork(hostId);
    const neighbors = this.getNeighborNetworks(network || '');
    if (proc.verdict === 'critical') {
      this.state.score -= 70;
      this.state.noise = Math.min(10, this.state.noise + 2);
      if (network) this.state.access[network] = false;
      const collateral = neighbors.slice(0, 1);
      collateral.forEach((n) => { this.state.access[n] = false; });
      this.state.effectMessage = `Critical process ${processName} blocked on ${hostId}: outage propagated to ${[network, ...collateral].filter(Boolean).join(', ')}.`;
      return { process: processName, status: 'critical-stopped', malicious: false, impact: `Service outage risk increased. Collateral impact: ${collateral.join(', ') || 'local machine only'}.` };
    }
    if (proc.verdict === 'suspicious') {
      this.state.score += 26;
      const recovered = neighbors.find((n) => !this.state.access[n]);
      if (recovered) this.state.access[recovered] = true;
      this.state.effectMessage = `Blocked malicious process ${processName} on ${hostId}. Lateral movement to linked machines interrupted.`;
      return {
        process: processName,
        status: 'malicious-stopped',
        malicious: true,
        impact: `Malicious execution chain interrupted.${recovered ? ` Restored access for ${recovered}.` : ''}`
      };
    }
    this.state.score -= 6;
    this.state.noise = Math.min(10, this.state.noise + 1);
    const degraded = neighbors[0];
    if (degraded) this.state.effectMessage = `${processName} looked legitimate; dependent service in ${degraded} degraded.`;
    else this.state.effectMessage = `${processName} looked legitimate; review before blocking next time.`;
    return {
      process: processName,
      status: 'benign-stopped',
      malicious: false,
      impact: `A legitimate process was stopped; ${degraded ? `${degraded} services may degrade too.` : 'local services may degrade.'}`
    };
  }


  getHostNetwork(hostId) {
    return this.seededHosts.hostMap.find((h) => h.id === hostId)?.network || null;
  }

  getNeighborNetworks(network) {
    return FIREWALL_LINKS
      .filter((l) => l.a === network || l.b === network)
      .map((l) => (l.a === network ? l.b : l.a));
  }

  runMachineOperation(hostId, operation) {
    const network = this.getHostNetwork(hostId);
    if (!network) return { ok: false, text: 'Unknown machine operation target.' };

    const loseNetwork = (n) => { if (n) this.state.access[n] = false; };
    const recoverNetwork = (n) => { if (n) this.state.access[n] = true; };
    const addEvidence = (ip, path) => {
      if (ip && !this.state.evidence.maliciousIps.includes(ip)) this.state.evidence.maliciousIps.push(ip);
      if (path && !this.state.evidence.executionPaths.includes(path)) this.state.evidence.executionPaths.push(path);
    };

    const op = {
      'trace-route': () => {
        this.state.score += 16;
        this.state.noise = Math.max(0, this.state.noise - 1);
        this.revealNextKillChainStage();
        addEvidence(null, `route:${network}:tracert 10.10.66.77`);
        return { ok: true, command: 'tracert 10.10.66.77', text: 'Router path is tampered. Evidence gained: network rules compromised.' };
      },
      'aggressive-scan': () => {
        this.state.noise = Math.min(10, this.state.noise + 3);
        this.state.score -= 24;
        loseNetwork(network);
        const impacted = this.getNeighborNetworks(network).slice(0, 1);
        impacted.forEach(loseNetwork);
        return { ok: true, command: `nmap -p 1-65535 -T 4 ${hostId}`, text: `EDR triggered. Access degraded in ${[network, ...impacted].join(' and ')}.` };
      },

      'audit-mail-rules': () => {
        this.state.score += 18;
        this.revealNextKillChainStage();
        addEvidence('185.55.55.10', 'mail:corp-hr-01:forward-rule');
        return { ok: true, command: 'Get-InboxRule -Mailbox hr@corp.local', text: 'Found malicious forwarding rule from HR mailbox to attacker node.' };
      },
      'reset-krbtgt': () => {
        this.state.score += 12;
        this.state.noise += 1;
        recoverNetwork('corp');
        loseNetwork('drone');
        return { ok: true, command: 'Reset-KrbtgtKeys -Force', text: 'Domain tickets reset. Corp stabilizes, but drone mission auth must be re-established.' };
      },
      'restore-fileshare-acl': () => {
        this.state.score += 22;
        recoverNetwork('corp');
        recoverNetwork('ot');
        return { ok: true, command: 'icacls \corp-fs-02\shared /restore backup.acl', text: 'FileServer ACL restored. HR and OT historian sync can use shares again.' };
      },

      'flush-dns-poison': () => {
        this.state.score += 18;
        recoverNetwork('provider');
        recoverNetwork('corp');
        addEvidence('185.17.44.9', 'dns:prov-dns-01:poisoned-cache');
        return { ok: true, command: 'rndc flush && rndc reload', text: 'Poisoned DNS cache removed. Public and corporate endpoints recover routing.' };
      },
      'enable-fw-hunt': () => {
        this.state.score += 10;
        this.state.firewall['provider-corp'] = 'monitor';
        this.state.firewall['provider-drone'] = 'monitor';
        return { ok: true, command: 'fwctl profile threat-hunt --mode monitor', text: 'Firewall moved to hunt mode on provider links; traffic kept alive for intel capture.' };
      },
      'proxy-cache-triage': () => {
        this.state.score += 15;
        addEvidence('104.23.201.7', 'proxy:prov-proxy-01:unsigned-package');
        return { ok: true, command: 'proxyctl cache audit --top-talkers', text: 'Proxy cache reveals unsigned package fetches from suspicious CDN endpoint.' };
      },

      'ot-safe-mode': () => {
        this.state.score += 8;
        this.state.otRisk = Math.max(0, this.state.otRisk - 2);
        loseNetwork('ot');
        return { ok: true, command: 'scadactl set safety-mode on', text: 'ICS entered safety mode: turbine writes stopped, but OT services are temporarily unavailable.' };
      },
      'recover-historian-stream': () => {
        this.state.score += 20;
        recoverNetwork('ot');
        recoverNetwork('corp');
        addEvidence(null, 'ot-historian:replayed-gap-window');
        return { ok: true, command: 'historiandiff --repair --window 4h', text: 'Historian telemetry repaired. Corp analytics and OT trend monitoring restored.' };
      },
      'isolate-substation-link': () => {
        this.state.score += 6;
        this.state.otRisk = Math.max(0, this.state.otRisk - 1);
        loseNetwork('ot');
        loseNetwork('corp');
        return { ok: true, command: 'gatewayctl isolate-link --peer corp', text: 'Substation isolated from corp. Attack path interrupted, but corp-OT services are down.' };
      },

      'rotate-uav-keys': () => {
        this.state.score += 18;
        recoverNetwork('drone');
        addEvidence('172.23.99.41', 'drone-relay:key-abuse');
        return { ok: true, command: 'uavctl key-rotate --all-relays', text: 'Telemetry keys rotated. UAV channel recovers and hostile relay can no longer authenticate.' };
      },
      'rollback-flight-plan': () => {
        this.state.score += 10;
        this.state.noise = Math.min(10, this.state.noise + 1);
        loseNetwork('drone');
        return { ok: true, command: 'missionctl rollback --last-known-good', text: 'Flight plan rollback prevented malicious route updates, but active drone missions paused.' };
      },
      'quarantine-archive-packages': () => {
        this.state.score += 14;
        recoverNetwork('drone');
        recoverNetwork('provider');
        return { ok: true, command: 'archivectl quarantine --unsigned', text: 'Unsigned UAV packages quarantined. Drone archive sync recovered across provider relay.' };
      }
    }[operation];

    if (!op) return { ok: false, text: 'Unsupported machine operation.' };
    const result = op();
    this.state.effectMessage = result.text;
    return result;
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
