# Start here — continuing the evil-twin project on a new account

Read in this order:
1. `EVIL-TWIN-SESSION-LOG.md` — everything built (attack + defense + consoles).
2. `CLAUDE.md` — how to operate in this repo.
3. `EVIL-TWIN-CONCEPTS.md` — detection reasoning.
4. `memory/` — persistent context from the other account (MEMORY.md is the index).
   Tell your new Claude: "read the files in memory/ to get up to speed."

To RUN it you need the code too (already included): `evil_twin_detect.py`,
`portal/`, `defense/`, and the `*.sh` launchers. See §6 of the session log.

Pending next task: guardian.py device fingerprinting + known_devices.json routing
+ deauth fallback (see memory/project_notification_delivery.md).
