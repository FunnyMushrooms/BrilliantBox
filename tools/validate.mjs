import fs from 'node:fs';

function loadScenario() {
  const manifest = JSON.parse(fs.readFileSync(new URL('../data/scenario.json', import.meta.url), 'utf8'));
  const fragments = manifest.fragments.map((name) =>
    JSON.parse(fs.readFileSync(new URL(`../data/scenario_fragments/${name}.json`, import.meta.url), 'utf8'))
  );
  const nodes = fragments.reduce((acc, fragment) => ({ ...acc, ...fragment.nodes }), {});
  return { startNode: manifest.startNode, nodes };
}

const scenario = loadScenario();
const { nodes } = scenario;
const ids = new Set(Object.keys(nodes));
const errors = [];

for (const [id, node] of Object.entries(nodes)) {
  for (const opt of node.options || []) {
    if (!ids.has(opt.next)) errors.push(`Missing next node from ${id} -> ${opt.next}`);
    if ((opt.timeCostSec || 0) <= 0) errors.push(`Non-positive timeCostSec at ${id} :: ${opt.label}`);
  }
}

const seen = new Set();
const stack = [scenario.startNode];
while (stack.length) {
  const nodeId = stack.pop();
  if (seen.has(nodeId)) continue;
  seen.add(nodeId);
  for (const opt of nodes[nodeId]?.options || []) stack.push(opt.next);
}

for (const id of ids) if (!seen.has(id)) errors.push(`Unreachable node ${id}`);

for (const [id, node] of Object.entries(nodes)) {
  for (const opt of node.options || []) {
    if (opt.next === id) errors.push(`Self loop detected at ${id}`);
  }
}

const canReachWin = (() => {
  const memo = new Map();
  function dfs(nodeId, depth = 0) {
    if (depth > 700) return false;
    if (memo.has(nodeId)) return memo.get(nodeId);
    const node = nodes[nodeId];
    if (!node) return false;
    if (node.type === 'win') return true;
    memo.set(nodeId, false);
    const reachable = (node.options || []).some((opt) => dfs(opt.next, depth + 1));
    memo.set(nodeId, reachable);
    return reachable;
  }
  return dfs(scenario.startNode);
})();

if (!canReachWin) errors.push('No reachable win path from start');

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(`Scenario validation passed. nodes=${ids.size} reachable=${seen.size}`);
