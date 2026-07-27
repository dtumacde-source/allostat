# Allostat

**An allostatic regulator for AI coding agents.** Allostat gives Claude Code a
nervous system — autonomic memory, drift correction, and session-to-session
continuity that fires through hooks, with no agent invocation required.

Your memory stays on your machine. The regulator runs as a hosted service that
this plugin connects to. Learn more at **[allostat.ai](https://allostat.ai)**.

---

## What it does

- **Remembers across sessions** — your work carries forward on its own. No cold
  starts, no re-explaining the project every morning.
- **Makes corrections stick** — fix something once and Allostat flags it if the
  old mistake tries to creep back. Recurring corrections can become standing
  rules, only with your approval.
- **Catches the catastrophic** — a fixed set of guardrails watches every action.
  A few genuinely irreversible moves are blocked; the rest just add a heads-up.
  Everyday work is never in the way.
- **Keeps your memory healthy** — near-duplicate notes, stale rules, and orphaned
  files are surfaced for a graceful, approve-first cleanup. Nothing is ever
  deleted out from under you.
- **Keeps projects separate** — no context bleeding between unrelated work.
- **Keeps your files on your machine** — Allostat reads only what it needs in the
  moment. Nothing is stored on our servers.

## Install (Claude Code plugin marketplace)

```
/plugin marketplace add dtumacde-source/allostat
/plugin install allostat-mcp@allostat
/allostat-activate <your-install-code>
```

Then fully restart Claude Code so the plugin picks up your access token. Your
install code comes with your Allostat subscription — [request early
access](https://allostat.ai) if you don't have one yet.

Prefer a one-line installer or a manual download? See the full
[install guide](https://allostat.ai/install.html).

## What's in this repo

- **`allostat-mcp/`** — the Claude Code plugin: hooks, commands, skills, and the
  client-side library. This is the open client.
- **`.claude-plugin/marketplace.json`** — the marketplace manifest.

The regulator server is a separate, closed component. This repo is the client
that connects to it; without a valid subscription the plugin stays dormant and
silent.

---

© 2026 [Health Professions Data LLC](https://healthprofessionsdata.com) · Dominick Tumacder
