# Start here — continuing the evil-twin project on a new account

Read in this order:
1. `EVIL-TWIN-SESSION-LOG.md` — everything built (attack + defense + consoles).
2. `CLAUDE.md` — how to operate in this repo.
3. `EVIL-TWIN-CONCEPTS.md` — detection reasoning.
4. `memory/` — persistent context from the other account (MEMORY.md is the index).
   Tell your new Claude: "read the files in memory/ to get up to speed."

To RUN it you need the code too (already included): `evil_twin_detect.py`,
`portal/`, `defense/`, and the `*.sh` launchers. See §6 of the session log.

Guardian build DONE: device fingerprinting (OUI + randomized-MAC flag) + deauth
containment were already in; known_devices.json per-device routing added
2026-10-01 — a known MAC is named + warn-only (or opt-in contain), unknown MACs
fall back to deauth. Config: copy defense/known_devices.example.json →
defense/known_devices.json (gitignored). Hot-reload: POST /api/known.
