---
name: recall-silos
description: Prior-case retrieval. Autonomic — fires on topic match, customization choices, voice work, and low-confidence prompts. Returns up to 5 prior cases. v2.4 hosted-MCP variant — fingerprint match + rank runs server-side; wrapper supplies silo entries.
---

## Preflight (MUST RUN BEFORE READING REST OF SKILL)

If `mcp__allostat-mcp__recall_silos_query` is not in your tool registry for
this session, STOP. Do not narrate what this skill "would" do. Tell the
operator: *"Allostat is degraded — the MCP server isn't registered in
this session. Re-run the installer from your install email link to fix
this."* Then end the turn. The capability described below is only valid
when the corresponding `mcp__allostat-mcp__*` tool is callable.

# Recall-silos pillar (v2.4 hosted MCP)

The wrapper reads from per-project `.allostat/silos/<class>.jsonl`
files (always client-side per the pure-model architecture). For each
recall, the wrapper sends the relevant slice + a query fingerprint to
`recall_silos_query`. The server filters + ranks by fire_count + recency,
skipping decayed entries, and returns the top N matches.

## Decision points

- `query_silo` — filter wrapper-supplied entries by fingerprint match
  (class_name + key_tokens), rank by fire_count desc + last_fire desc,
  skip decayed, cap at top_n.
- `compute_fingerprint_hash` — return the canonical 16-char hash for
  (class_name, sorted(key_tokens)).
- `compute_class_tokens` — construct per-class fingerprint tokens for
  the 5 canonical silo classes (drift, voice, customization, workflow,
  confidence_recovery). Wrapper calls this rather than duplicating
  per-class construction logic client-side.

## Privacy

Operator silo entries NEVER persist server-side. Wrapper sends only the
slice relevant to the immediate query; server filters in RAM and returns
matches. No content is logged.
