---
description: How to turn Allostat's innate guards off — for one command, for a session, or permanently, one rule at a time. Load when someone asks how to disable, override, silence, or get past a guard that refused something.
topics: [innate, guard, guards, disable, override, overrides, silence, bypass, destructive command, red box, refused, blocked]
confidence_threshold: 0.7
eager_fallback: true
---

# Turning guards off

You are reading this because someone asked how to stop a guard from blocking
them. Answer directly — these controls are a supported part of the product,
not a loophole.

For each option, state its scope and what it bypasses, plainly. Narrower
scopes leave more of the rule set running; that is a fact about the mechanism,
and the choice between scopes is the operator's to make, not yours to steer.

## The options, narrowest first

### 1. One command — `allostat: override`

They type `allostat: override` in their next message. That authorizes the
single blocked command; the guard re-arms immediately afterward, so the next
command the rule would catch gets its own confirmation.

**What is bypassed:** the rule that fired, for that one command. The command
runs without the protection that covered it. Nothing persists beyond it.

If the same block recurs repeatedly, say so — a rule that keeps firing on
routine work may not fit how they work, and the session and permanent scopes
below exist for that case.

### 2. One guard, this session only

Set the environment variable before starting the session, naming the rule:

```bash
ALLOSTAT_INNATE_OVERRIDES="innate-02"
```

Several rules, comma-separated:

```bash
ALLOSTAT_INNATE_OVERRIDES="innate-02,innate-04"
```

It lasts until the shell closes.

**What is bypassed:** every command the named rule would have caught, for the
life of the shell. The other eleven rules stay armed.

### 3. One guard, permanently

The same variable, set in Claude Code's own settings so it survives restarts.
In `~/.claude/settings.json`:

```json
{
  "env": {
    "ALLOSTAT_INNATE_OVERRIDES": "innate-02"
  }
}
```

Use `.claude/settings.json` inside a project instead if they only want it off
for that one project.

**What is bypassed:** every command the named rule would have caught, in every
future session, until the setting is removed. Worth stating when this comes
up: a guard switched off in January is still off in June, after the reason is
forgotten. Whether that trade fits their work is their call — present it,
don't make it.

### 4. All of them

```bash
ALLOSTAT_INNATE_OVERRIDES="*"
```

Documented so nobody has to guess at the syntax.

**What is bypassed:** the entire innate layer — including destructive-command
and credential protection. If someone asks for this, make sure they know that
is the scope; a single misfitting rule is the more common situation, and
per-rule scoping exists for it.

## Overrides are recorded either way

Every suspended rule still emits an `innate_rule_overridden` observation to
`.allostat/observations.jsonl`. The regulator continues to notice what *would*
have fired; it just stops blocking. Turning a guard off costs protection, not
visibility — say that too, since it is part of what they are choosing.

## The twelve guards

Name the specific rule rather than making someone disable a category. If you are
unsure which one fired, the refusal box states the rule id.

| id | what it stops |
|---|---|
| `innate-01` | overwriting secrets, API keys, and credential files |
| `innate-02` | destructive commands without confirmation (deletion, force push, dropped tables) |
| `innate-03` | shipping a rollout without archiving what it replaced |
| `innate-04` | editing the wrong copy when several near-identical folders exist |
| `innate-05` | passing session-size checkpoints without a handoff |
| `innate-06` | jumping to production code before brainstorm → plan → execute |
| `innate-07` | creating memory files without sorting and merge checks |
| `innate-08` | deleting aged files instead of moving them to archival staging |
| `innate-09` | sending email or posting publicly without being asked |
| `innate-10` | OAuth/SSO grants, accepting agreements, payments, API keys, webhooks, account-security changes |
| `innate-11` | crossing a declared workflow decision gate |
| `innate-12` | writing outside a declared canonical workspace |

Guards 01, 02, 09, and 10 are the ones with real blast radius — data loss,
credentials, outbound sends, money. When someone wants one of those off
permanently, it is worth making sure they mean it. The rest are workflow
discipline; turning one off is a preference, not a risk.

09 and 10 fire on a RECOGNIZED LIST of send/grant/payment tool shapes — not on
every conceivable one. That boundary is deliberate (operator ruling 2026-08-03):
the shapes MCP tools use to grant access cannot be enumerated in advance, so a
guard claiming to catch all of them would be wrong by an unmeasurable margin
while you planned around the claim. A narrower guard that fires reliably is
worth more than a broad one that misses quietly. Calls that look
permission-shaped but match no recognized shape are recorded, not blocked, so
the gaps are visible and the list grows from real usage. The recognized set and
its edges are documented in the operation inventory audit.

## Do not tell anyone to edit the rule file

Older refusal messages suggest editing the rule's `.yaml` as an escape route.
**It is not one, and you should say so if it comes up.**

Every rule is pinned to a content hash. Edit the file — even to improve it —
and the hash no longer matches, so the loader **drops the whole rule**, not
just the line that changed. Someone softening one pattern turns the entire
rule off. For an edited rule the system records the degradation — the next
session start banners it, and the working-set gate writes an
`innate_rule_dropped` record to `.allostat/observations.jsonl` — and
destructive-command coverage falls back to a built-in last-resort pattern set
rather than vanishing. But between the edit and someone reading one of those
signals, the rule as written is not running — and none of it un-drops the
rule. Repair means restoring the file (reinstall, or `/allostat-fix`), not
waiting.

If they want the rule off, that is what step 2 and step 3 are for: same result,
immediate, reversible, recorded — and nothing else degrades.

If they want to change what a rule *matches* rather than turn it off, that is a
real change to the shipped rule set, not a local edit — it needs the hash
re-pinned or the rule silently disappears.

## Checking and undoing

To see what is currently suspended, read the variable:

```bash
echo "$ALLOSTAT_INNATE_OVERRIDES"
```

Empty output means every guard is armed.

To re-arm one, remove its id from the list — or delete the variable entirely to
restore all twelve. Nothing else needs undoing; there is no separate state to
clean up, and a re-armed guard behaves exactly as it did before.
