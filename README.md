# Incident Cartoon Defender

Story-driven Blue Team incident-response simulation built as a pure static GitHub Pages app (HTML/CSS/JS, no backend).

## Run locally
```bash
python -m http.server 8080
# open http://localhost:8080/
```

## Deploy to GitHub Pages
1. Push this repository.
2. In **Settings → Pages**, choose branch root (`/`).
3. Entry point is `index.html` in repo root.
4. Open `https://funnymushrooms.github.io/BrilliantBox/`.

## Subpath safety
All imports/requests use relative paths (`./src/...`, `./data/...`) so deployment under repository subpaths works.

## Scenario structure (split by functionality)
To avoid one oversized scenario file, scenario data is split:
- `data/scenario.json` (manifest)
- `data/scenario_fragments/core.json`
- `data/scenario_fragments/provider.json`
- `data/scenario_fragments/corp.json`
- `data/scenario_fragments/ot.json`
- `data/scenario_fragments/drone.json`

At runtime, fragments are merged into one graph.

## Validate scenario graph
```bash
node tools/validate.mjs
```
Checks references, reachability, positive action time costs, and reachable win path.

## Remote leaderboard (optional)
- Disabled by default in `config.json`.
- Set `remoteLeaderboard.enabled` to `true` and update endpoint.
- `remote/worker.js` includes a Cloudflare Worker example.

## Demo route (~6 minutes)
1. Provider Hub → **provider DNS anomaly triage** → targeted profile.
2. Corporate IT Hub → **EDR process lineage hunt** → targeted profile.
3. DroneOps Hub → **lab endpoint EDR sweep** → targeted profile.
4. OT Hub → **historian trend anomaly** → targeted profile.
5. Run **final assessment** → coordinated containment.

If you reached >=8 infected hosts, this is a standard win. For perfect win, find >=12 and stop detonation.

## Safety
All command previews are fictional and non-actionable, focused on defensive decision-making in a simulation.
