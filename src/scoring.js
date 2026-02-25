export function getScoreBreakdown(state) {
  const infected = state.foundHosts.length * 120;
  const timeBonus = Math.floor(state.timeLeftSec / 5);
  const stealthBonus = Math.max(0, (10 - state.noise) * 15);
  const otSafetyBonus = Math.max(0, (10 - state.otRisk) * 12);
  const templateBonus = state.inventory.includes('ioc-template') ? 80 : 0;
  const detonationStop = state.flags.stoppedDetonation ? 300 : 0;
  const total = infected + timeBonus + stealthBonus + otSafetyBonus + templateBonus + detonationStop + state.score;
  return { infected, timeBonus, stealthBonus, otSafetyBonus, templateBonus, detonationStop, total };
}
