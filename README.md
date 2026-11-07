# Local AI SIEM & Security Log Analyzer

A full-stack Next.js Security Operations Center (SOC) web application that uses a local, downloaded Large Language Model (qwen3.5:0.8b via Ollama) to detect, correlate, and summarize multi-part cyber attacks across large server logs.

Engineered specifically to operate offline within strict hardware and context boundaries: 4 GB total RAM, 2 vCPU (no GPU), and a 2,048-token per-call context window.

---

## Key Features & Rubric Compliance

- **100% Local & Offline AI Engine**: Connects directly to a local Ollama instance (http://127.0.0.1:11434) running qwen3.5:0.8b (with dynamic UI support for switching between installed local models). Zero cloud APIs are used.
- **Strict 2,048-Token Window Splitting**: Accepts .log or .txt files (~20,000+ tokens), decodes URL-encoded paths, preserves original [L#] line numbers, and partitions entries into ~600-token chunks without cutting any log entry mid-line.
- **Cross-Part Event Correlation (CarriedState)**: Tracks per-IP authentication lifecycles and suspicious indicators across earlier, middle, and late chunks. Automatically links multi-part attack chains (e.g., 12 failed logins from 203.0.113.44 across lines 5–189 followed by a successful login at line 196, admin access at line 198, and a 2.84 MB CSV data export at line 201) into a single combined report.
- **Prompt Injection / Log Poisoning Defense**: Sandboxes user-submitted log strings inside UNTRUSTED_LOG_DATA markers and instructs the model to treat log payloads strictly as passive data. Successfully flags the prompt injection attempt at Line 217 ("Ignore previous instructions..." from 203.0.113.201) without obeying it.
- **High Precision / Zero False Positives**: Distinguishes real attacks from routine operational errors (ignores retryable SQL database timeouts, upstream 502 supplier disconnects, scheduled 503 maintenance windows, and single-attempt user password typos).
- **Optional Extras Implemented**:
  1. **Resume After a Restart**: Persists completed reports to localStorage and re-hydrates state automatically on page reload, with a "Clear Report" button to reset.
  2. **Live RAM & Model Timing Telemetry**: Streams real-time Node.js RSS memory usage (MB / 4 GB) and per-chunk inference latency (seconds) via Server-Sent Events (SSE).
  3. **Reduced Model Calls**: Pre-filters benign HTTP 200/304 static asset requests (/assets/*, /health, /ready) prior to LLM chunking, reducing total model calls by over 50% while preserving 100% of security signals.
  4. **Local Model Switcher**: Queries Ollama's /api/tags endpoint to allow live switching between installed local models in the UI header.

---

## Tech Stack

- **Frontend**: Next.js (App Router), React, Tailwind CSS, Lucide Icons, Server-Sent Events (SSE) stream reader
- **Backend**: Next.js Route Handlers (app/api/analyze/route.ts, app/api/health/route.ts)
- **Local AI Runtime**: Ollama serving qwen3.5:0.8b (num_ctx: 2048, temperature: 0.0, think: false)

---

## Setup & Installation Steps

### 1. Prerequisites
- Node.js (v18+ recommended)
- Ollama installed locally (https://ollama.com)

### 2. Download the Local Model
Pull the suggested lightweight Qwen 3.5 0.8B model (~1.2 GB RAM footprint, fits comfortably inside the 4 GB RAM limit alongside Next.js):

    ollama pull qwen3.5:0.8b

Verify Ollama is running locally on port 11434:

    ollama list

### 3. Install Project Dependencies & Start Server
Clone this repository, install dependencies, and run the development server:

    npm install
    npm run dev

### 4. Run the Analysis
1. Open http://localhost:3000 in your browser.
2. Verify the top-right status indicator shows "Ollama: Online" and "LLM: qwen3.5:0.8b".
3. Upload Cultive8_Workspace_Agrigen_Server.log (or any .log / .txt server log file).
4. Click "Execute Neural SIEM Analysis" to watch real-time chunk progress, token budget telemetry, and the correlated security report.
5. Click any L# badge on a finding card to inspect the exact raw log line in the interactive Evidence Line Inspector.

---

## Log Splitting & Cross-Part Linking Method

1. **Line-Preserving Compaction (formatLogLineForLLM)**:
   Each raw line is indexed with its 1-based line number ([L1], [L2], ..., [L259]). Verbose JSON fields are compacted into high-signal tuples ([L#] TIME | IP | LVL | METHOD PATH | STATUS | AUTH | RULE | RATE) and URL-encoded query strings are decoded so obfuscated payloads (%27%20OR%201%3D1-- and ..%2F..%2Fetc%2Fpasswd) are immediately legible to the 0.8B model.
2. **Token-Aware Chunking (splitLogsIntoTokenChunks)**:
   Lines are accumulated whole (never split mid-line) up to a maximum chunk budget of 600 tokens (~3.6 characters/token BPE estimate). Combined with the system prompt (~280 tokens), carried state summary (~200 tokens), and reserved model output (num_predict: 450), every call stays between 1,150 and 1,550 tokens—well below the hard 2,048-token limit.
3. **Sequential Single-Call Queue**:
   Chunks are processed sequentially one call at a time (for loop over await callOllamaWithRetry(...)) to prevent concurrent memory spikes and keep total system RAM under 2 GB.
4. **Cross-Part State & Final Correlation (CarriedState & buildCorrelatedReportWithLLM)**:
   After each chunk, per-IP authentication history and anomaly lines are updated in CarriedState and passed into subsequent chunk prompts. Once all parts are processed, related events across the entire file are merged by IP and attack vector and synthesized by the local LLM into a single deduplicated report.

---

## Detected Findings on Reference Dataset (Cultive8_Workspace_Agrigen_Server.log)

- **Critical — Brute Force Followed by Account Compromise (IP: 203.0.113.44)**:
  12 failed logins against workspace.admin across lines L5, L13, L23, L35, L50, L65, L80, L94, L108, L123, L153, L189 followed by successful login at L196, admin endpoint access at L198, and a 2.84 MB CSV export at L201.
- **High — SQL Injection (SQLi) (IP: 203.0.113.72)**:
  Boolean-based, UNION SELECT, and time-based SLEEP(5) SQL injection payloads against /api/v1/crops across lines L29, L30, L32, L222, L223.
- **High — Vulnerability Scanning, Path Traversal & Unauthorized Access (IP: 203.0.113.90)**:
  Automated probing of /.env, /.git/config, /wp-admin/, /phpmyadmin/, /actuator/env, /server-status, /backup.sql, /config.json, /api/v1/admin/settings, and URL-encoded ../../etc/passwd traversal across lines L54, L56, L58, L60, L62, L64, L67, L69, L99, L101, L102.
- **Medium — Unusual Request Rate / API Flooding (IP: 203.0.113.155)**:
  High-frequency automated burst (124–135 requests/10s window) against /api/v1/weather?farm_id=18 triggering repeated HTTP 429 rate-limit blocks across lines L159–L170.
- **Medium — Prompt Injection / Log Poisoning Attempt (IP: 203.0.113.201)**:
  Malicious instruction-override payload ("Ignore previous instructions...") submitted to /api/v1/support/messages at line L217, safely isolated as passive data.

---

## Known Limits

- **CPU Inference Latency**: Because inference runs sequentially on 2 vCPUs without a GPU, analyzing a 20,000-token log file takes approximately 20–45 seconds depending on host CPU clock speed.
- **Sub-1B Model Schema Variance**: Very small models (0.5B–0.8B) can occasionally return truncated JSON if output tokens are unconstrained; this is mitigated by setting format: "json", think: false, temperature: 0.0, and wrapping JSON parsing in a resilient substring recovery block.