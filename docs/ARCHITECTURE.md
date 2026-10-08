# Architecture, Guardrails & Change Process

This document covers how the SOAR engine is designed, how I constrained the AI step, and how changes move from development to production. The [README](../README.md) gives the overview, and the full technical writeup is in `report/`.

---

## 1. High-Level Design (HLD)

### 1.1 Purpose

The pipeline automates the first two stages of incident response for one type of detection: a web path traversal used for local file inclusion (LFI) against DVWA. It triages a Splunk alert, decides whether it needs a human's attention, and, only if a human approves, blocks the attacker's IP at the perimeter firewall.

I didn't make it fully autonomous on purpose. The one step that changes something on the network always waits for a person.

### 1.2 System context

```
┌────────────┐     webhook      ┌─────────────────────────┐
│   Splunk   │ ───────────────▶ │  n8n (orchestrator)      │
│  (SIEM)    │ ◀─────────────── │  UID 1000, non-root      │
└────────────┘   audit writeback└───────────┬──────────────┘
                                             │ file IPC (/app/input.json)
                                             ▼
                                 ┌──────────────────────────┐
                                 │ Docker sandbox            │
                                 │ python:3.11-slim, ephemeral│
                                 │ sandbox_analyzer.py        │
                                 └───────────┬────────────────┘
                                    is_malicious? ──false──▶ log + stop
                                             │ true
                                             ▼
                                 already blocked? ──yes──▶ log + stop
                                             │ no
                                             ▼
                                 ┌──────────────────────────┐
                                 │ Claude API (triage)       │
                                 │ claude-sonnet-4-5         │
                                 └───────────┬────────────────┘
                                    severity < HIGH? ──yes──▶ log + stop
                                             │ CRITICAL/HIGH
                                             ▼
                                 ┌──────────────────────────┐
                                 │ Discord HITL gate          │
                                 │ Approve / Decline buttons  │
                                 └───────┬─────────┬──────────┘
                                    Approve      Decline
                                         │             │
                                         ▼             ▼
                              ┌────────────────┐  log + stop
                              │ pfSense REST API │
                              │ alias PATCH,      │
                              │ apply: true        │
                              └────────────────────┘
```

### 1.3 Components and trust boundaries

| Component | Role | Trust boundary |
| --- | --- | --- |
| Splunk | Detection source and audit sink | Trusted internal source; the only thing that can trigger the pipeline |
| n8n | Orchestrator; stores no AI or firewall credentials in plaintext | Runs as non-root (UID 1000); Docker socket access through group mapping, not root |
| Docker sandbox | Local risk scoring, the first filter | Ephemeral, non-root container; doesn't need network access |
| Claude API | Triage and classification only | Outbound call only; it never gets write access to anything (see section 3) |
| Discord | Where a human approves or declines | Bot limited to 4 permissions (Send Messages, Embed Links, Read Message History, Add Reactions); no server or member management |
| pfSense | Enforcement | The only component that can change network behaviour, and only reached after human approval |

### 1.4 Data flow: five possible outcomes, all logged

1. Benign: suppressed at the sandbox, no LLM call.
2. Already blocked: suppressed after the alias check, no LLM call.
3. Low or medium severity: logged after triage, no human is paged.
4. High or critical, and the human declines: logged, no firewall change.
5. High or critical, and the human approves: the pfSense alias is patched with `apply: true`.

All five outcomes are written to a dedicated `soar_audit` index in Splunk through the HTTP Event Collector, so every alert ends with a record, whether or not it reached a human.

I added this in Module 6. Before that, every decision ended in n8n's own execution history, which was fine for debugging during the build but didn't give a lasting, searchable record. All five branches lead to one shared "Send to Splunk" node instead of five separate HTTP Request nodes. That way there's one place to change the HEC endpoint or the payload, and every event gets the same index, source type and auth header.

---

## 2. Low-Level Design (LLD)

### 2.1 Ingestion (n8n)

The Splunk webhook reaches n8n, which extracts `src_ip`, `uri` and `raw_log` and writes them to a shared volume as `/app/input.json`. I used a file for this instead of passing the values as command-line arguments, so that nothing in the alert can be injected into the command that starts the sandbox.

### 2.2 Sandbox risk scoring (`sandbox_analyzer.py`)

This runs in an ephemeral, non-root `python:3.11-slim` container. It reads `input.json` and returns a structured verdict (`is_malicious` and a risk score).

This is the pre-LLM suppression step. Its job is to make sure that a flood of routine or spoofed traffic doesn't turn into API costs or alert fatigue.

### 2.3 Early-block check (n8n Code node)

Before Claude is called, n8n GETs the current `SOAR_Blocklist` alias from pfSense by its numeric ID and checks whether `extracted_ip` is already in the list. If it is, the workflow skips straight to logging.

I moved this check ahead of the AI step in Module 4, after noticing that already-blocked IPs were still costing an API call each.

### 2.4 AI triage (Claude API)

The model is `claude-sonnet-4-5`. An earlier build used the alias `claude-3-5-sonnet-latest` and got intermittent 404 errors, so I switched to a specific, active model ID.

Claude is called with a strict system prompt that only allows a JSON answer. The answer contains the severity, the MITRE ATT&CK mapping, a plain-language summary, a recommended action and the extracted attacker IP.

### 2.5 Severity gate (n8n If node)

The `severity` field is matched against the regex `^(CRITICAL|HIGH)$`. Anything below HIGH is logged, and no human is paged.

I ran into a bug here in Module 4: I had used "is equal to" with a regex string, which quietly sent every alert down the false branch. Switching the condition to "matches regex" fixed it.

### 2.6 Human-in-the-loop gate (Discord)

This uses n8n's "send message and wait for response" node in Approval mode. The message shows the severity, MITRE technique, attacker IP, target URI, Claude's summary and the recommended action, so the reviewer doesn't need to open another tool to decide. The workflow stops here, and nothing after this point runs until someone clicks.

### 2.7 Enforcement (pfSense REST API)

This step only runs after approval. It PATCHes the `SOAR_Blocklist` alias instead of creating a new firewall rule for each alert. A single static block rule references the alias, so the actual blocking logic stays in one place that I can check in the pfSense GUI at any time.

Authentication uses the `X-API-Key` header. The request needs `"apply": true`, otherwise the change stays in pfSense's pending changes. The IP list is deduplicated with a `Set` before the PATCH.

---

## 3. Agent Guardrails

**The model can only answer, not act.** The AI step has exactly one capability: it gets a fixed, structured prompt and returns JSON. It can't call pfSense, post to Discord or write to Splunk. Every action that changes something is done by n8n or pfSense, never by the model.

**Least privilege everywhere, not only at the AI step.** n8n runs as non-root (UID 1000), with Docker socket access through group mapping. The Discord bot has four permissions and can't manage the server or its members. The pfSense API key is limited to a single alias operation, not general firewall administration.

**A human approves the one destructive action.** The pipeline suppresses, triages and logs on its own, but the firewall block always waits for a person. I chose this on purpose: in my view, automatically blocking a false positive is a bigger risk than responding a bit slower.

**An audit trail for every outcome.** Because all five outcomes in section 1.4 go to the `soar_audit` index, it's possible to answer "what did the AI decide, and did a human see it?" for every alert, not only the ones that led to a block. I tested this end to end with a real attack run (a fresh IP, approval in Discord, the pfSense change confirmed) and found the event afterwards with a plain search:

```spl
index=soar_audit status=BLOCK_APPLIED
```

`attacker_ip`, `severity` and `timestamp` came through as searchable fields.

**Limiting cost and misuse.** The sandbox scoring and the already-blocked check both run before the AI step, so the model can't be triggered at high volume. That keeps API costs down and makes token-exhaustion style abuse harder.

**A known limitation.** Updating the pfSense alias is a read-modify-write, so two blocks approved at the same moment could overwrite each other's IP. It's listed in section 5.

---

## 4. Dev → Int → Prod

**Current state:** the lab runs a single environment, so there's no real separation between dev, int and prod yet. Below is how I handle changes today, and how I'd extend that to separate stages.

**What I do today**

- I commit every workflow and script change to git before activating it in n8n. The exported workflow JSON is the source of truth, not whatever is live in the n8n editor.
- I test nodes with pinned data first because it's fast, but I only count a change as done once it has worked with a real, unattended trigger. The writeup describes a bug that pinned data would never have caught: Splunk was pointed at n8n's test webhook, which only listens while the editor is open.
- I write up bugs and their fixes in the same document as the feature (see `report/`), which works as a simple change log.

**How it could extend to dev, int and prod**

1. **Dev:** a local or shared dev n8n instance. Workflow JSON is edited and tested with pinned data here, and changes to the sandbox analyzer are covered by the tests in `tests/` before commit.
2. **Int:** the workflow JSON is promoted by merging a pull request into an `int` branch, then deployed to a staging n8n instance connected to a non-production Splunk index and a test Discord channel. It's verified with a real, unattended trigger, not only pinned data.
3. **Prod:** promotion is a tagged release. The production n8n instance only imports a tagged workflow export, never a change made live in the editor. The pfSense API key and Discord webhook in prod are separate from the ones in int, with the same scope but rotated independently.

Every stage uses the same workflow JSON file, promoted with a git tag instead of being edited by hand for each environment. That way, what runs in prod is the same thing that was tested in int.

---

## 5. Known limitations

| Limitation | Impact | Status |
| --- | --- | --- |
| The pfSense alias update is a read-modify-write, with a race condition under concurrent alerts | Two approvals at almost the same moment could overwrite each other's IP | Documented, not fixed. It's acceptable at lab alert volumes; a real deployment would need an atomic append endpoint or a lock |
| Only one detection type (path traversal / LFI) | The pipeline doesn't handle other alert types yet | Scoped this way on purpose for Project 4. Extending the sandbox analyzer's rules is the natural next step |
| No dev/int/prod separation yet | A live promotion pipeline can't be shown | See section 4. The process is documented but not yet built as separate environments |
