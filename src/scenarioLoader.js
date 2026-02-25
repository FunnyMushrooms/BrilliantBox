function mulberry32(a) {
  return function rng() {
    let t = (a += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashSeed(seed) {
  let h = 1779033703 ^ seed.length;
  for (let i = 0; i < seed.length; i += 1) {
    h = Math.imul(h ^ seed.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  return h >>> 0;
}

function mergeNodes(fragments) {
  return fragments.reduce((acc, fragment) => ({ ...acc, ...fragment.nodes }), {});
}

async function loadScenarioFromFragments() {
  const manifest = await fetch('./data/scenario.json').then((r) => r.json());
  const fragmentDocs = await Promise.all(
    manifest.fragments.map((name) => fetch(`./data/scenario_fragments/${name}.json`).then((r) => r.json()))
  );
  return {
    meta: manifest.meta,
    startNode: manifest.startNode,
    nodes: mergeNodes(fragmentDocs)
  };
}

export async function loadScenario() {
  const [scenario, hostPool, config] = await Promise.all([
    loadScenarioFromFragments(),
    fetch('./data/hostPool.json').then((r) => r.json()),
    fetch('./config.json').then((r) => r.json())
  ]);
  return { scenario, hostPool, config };
}

export function applySeed(hostPool, seed) {
  const rng = mulberry32(hashSeed(seed));
  const eligible = hostPool.hosts.filter((h) => h.eligibleInfected);
  const decoys = hostPool.hosts.filter((h) => h.decoy);

  const infectedCount = 8 + Math.floor(rng() * 5);
  const infected = new Set();
  while (infected.size < infectedCount && infected.size < eligible.length) {
    infected.add(eligible[Math.floor(rng() * eligible.length)].id);
  }

  const armedDecoys = new Set();
  const armedCount = Math.min(6, decoys.length);
  while (armedDecoys.size < armedCount) {
    armedDecoys.add(decoys[Math.floor(rng() * decoys.length)].id);
  }

  return { infected, armedDecoys, infectedCount };
}

export function validateScenarioShape(scenario) {
  if (!scenario.startNode || !scenario.nodes?.[scenario.startNode]) {
    throw new Error('Invalid scenario: missing start node');
  }
}
