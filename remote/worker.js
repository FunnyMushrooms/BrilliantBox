export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response('', { headers: cors() });
    if (request.method === 'POST') {
      const payload = await request.json();
      const key = `score:${Date.now()}:${Math.random().toString(36).slice(2, 6)}`;
      await env.LEADERBOARD.put(key, JSON.stringify(payload));
      return json({ ok: true });
    }
    if (request.method === 'GET') {
      const list = await env.LEADERBOARD.list({ prefix: 'score:' });
      const rows = await Promise.all(list.keys.slice(-25).map(async k => JSON.parse(await env.LEADERBOARD.get(k.name))));
      rows.sort((a, b) => b.score - a.score || b.timeLeftSec - a.timeLeftSec);
      return json(rows.slice(0, 10));
    }
    return new Response('Not found', { status: 404, headers: cors() });
  }
};

function json(data) {
  return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json', ...cors() } });
}
function cors() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}
