# Dashboard + AI — what's in the console (2026-10-01)

Summary of the UI redesign and the AI analyst, so both teammates are on the same page.
Our changes: `console.html`, `console.py`, `preview.html`, `defense/ai_analyst.py` (+ `test_ai_analyst.py`).

## Run it

```bash
# attacker box (Atheros AR9271 = wlan0)
sudo CON_ATTACK_IFACE=wlan0 ./start-console.sh        # http://127.0.0.1:8080
```
After editing files: restart the console and **hard-reload the browser once** (Ctrl+Shift+R).
No-backend visual preview (mock data, open in a browser): `preview.html`.

## Dashboard (`console.html`)

- Liquid-glass theme, left sidebar nav: **Overview · Red Team · Blue Team · Captures · Portal · AI**.
- **Overview (Live Ops):** dual-radio status, red+blue summary side-by-side, a phase strip
  (Recon › Attack › Detect › Warn), live activity (rogues blocklisted + latest attempt),
  console tail, and the AI "latest read".
- **Blue Team:** rogue list now shows the **AI verdict badge** per detection, plus an **analyst chat**.
- **Portal tab:** live victim-page preview in a phone frame + an in-dashboard **code editor**
  (edit & save `portal/*.html`). Served by the `/portal/<file>` route.
- **AI tab:** model picker (2 models), test connection, analyst chat, incident report.
- Resizable log rail (drag its left edge; height-capped so logs scroll inside the box).
- Action buttons show busy/disabled states (e.g. "scanning…", "twin live").
- The warning-**beacon** feature was removed from the UI.

## AI analyst (blue-team second opinion)

Local, **advisory only** — never controls detection/blocklist/deauth/attack. Degrades to
"unavailable" (detector verdict stands) if the model is unreachable.

- **Engine:** `defense/ai_analyst.py` (Ollama `/api/chat`, primary→fallback, bounded timeouts,
  background worker, circuit breaker). Wired into `console.py`.
- **Endpoint:** `http://100.70.174.44:11434` (Mac Mini M4 over Tailscale), health via `/api/tags`.
- **Models (default):** primary `qwen2.5:7b-instruct` (fast, ~8-12s), fallback
  `huihui_ai/qwen3.5-abliterated:9b-q4_K`. Override with `DEF_AI_PRIMARY` / `DEF_AI_FALLBACK`,
  or pick in the AI tab. The 9b alone was too slow (timed out at 20s), hence qwen2.5 first.
- **How it decides:** it reasons over the **detector's evidence** (new BSSID for a known SSID,
  WPA2→Open downgrade, unknown OUI, louder-than-real signal). **No training, no embeddings, no RAG.**
- **Where it shows:** per-detection verdict badges (Overview / AI tab / Blue list), analyst
  chat (AI + Blue tabs, grounded on a live situation brief, remembers the last few turns),
  one-click incident report.
- **Routes:** `GET /api/ai/health`, `POST /api/ai/chat` `{message, grounded, history}`,
  `POST /api/ai/report`, `POST /api/ai/config` `{enabled, model}`. The verdict is attached to
  each rogue in `/api/status` → `blue.evil[].ai`.
- **Env:** `DEF_AI=0` disables it; `DEF_AI_URL`, `DEF_AI_TIMEOUT`, `DEF_AI_PRIMARY`, `DEF_AI_FALLBACK`.
- Tests: `cd defense && python3 -m unittest test_ai_analyst` (28 OK).
  Live smoke: `python3 defense/ai_analyst.py --smoke`.

## Known lever (future)

Verdict quality is limited because the detector passes only `ssid/channel/crypto/reasons` to
the AI, not structured `known_network` (secured + peak_rssi). The reasons text covers most of
it; passing those fields would sharpen verdicts (small change on the detector side).
