const LB_KEY = 'icd_leaderboard_v1';
const SESSION_KEY = 'icd_session_v1';

export function loadLeaderboard() {
  try { return JSON.parse(localStorage.getItem(LB_KEY)) || []; } catch { return []; }
}

export function saveLeaderboard(entry) {
  const board = loadLeaderboard();
  board.push(entry);
  board.sort((a, b) => b.score - a.score || b.timeLeftSec - a.timeLeftSec);
  const top = board.slice(0, 10);
  localStorage.setItem(LB_KEY, JSON.stringify(top));
  return top;
}

export function saveSession(state) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(state));
}

export function loadSession() {
  try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch { return null; }
}
