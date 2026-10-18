# 🛡️ Tinyfah — Autonomous AI Web Vulnerability & Security Posture Auditor

> Built for **AZINHACK 2026** | Powered by **TinyFish Browser API (CDP)**, **Google Gemini 2.5 Flash**, **FastAPI**, and **Next.js**.

**Tinyfah** is an agentic web security auditing platform that inspects live websites using real cloud browser instances over the **Chrome DevTools Protocol (CDP)**. Instead of running a rigid, static checklist like legacy scanners, Tinyfah uses a **Gemini 2.5 Flash ReAct (Reason + Act) Agent Harness** that analyzes initial browser reconnaissance, dynamically selects and executes diagnostic CDP & DOM scripts based on live responses, and streams its reasoning trace in real time.

---

## ✨ Key Features

- 🌐 **Isolated Cloud Browser Execution (TinyFish API):** Spins up remote Chromium sessions on demand and connects via WebSocket `cdp_url`—no local headless browser overhead or SSRF risk.
- 🧠 **Adaptive ReAct Agent Harness (Gemini 2.5 Flash):** Evaluates HTTP headers and initial DOM recon, then autonomously decides which deep-dive tools to run (or writes custom read-only JS probes via `page.evaluate()`).
- 🔬 **Native Chrome DevTools Protocol (CDP) Telemetry:** Hooks directly into Chromium's `Audits`, `Network`, and `Security` CDP domains to capture `HttpOnly` cookie flags, Mixed Content, SameSite issues, and CSP violations that standard JS scripts cannot see.
- ⚡ **Live Agent Reasoning Timeline:** Streams intermediate agent thoughts, tool calls, and browser observations to SQLite (WAL mode) so the Next.js frontend displays live progress while polling.
- 📊 **Schema-Guaranteed Security Grading:** Uses Gemini's structured `Pydantic` output schema to calculate an overall score (`0–100`), letter grade (`A–F`), and actionable remediation steps.

---

## 🏗️ System Architecture

```text
+-------------------+       POST /scans (URL + Focus)       +-----------------------+
|   Next.js Client  | ------------------------------------> |    FastAPI Backend    |
| (localhost:3000)  | <------------------------------------ |       (main.py)       |
+-------------------+     GET /scans/{id} (2s Polling)      +-----------+-----------+
                                                                        |
                                           FastAPI BackgroundTasks      |Read/Write
                                                                        v
+-----------------------------------------------------------+     +-----+---------------+
|              Scanner & Gemini Agent Harness               |     |   SQLite Database   |
|         (scanner.py + agent_harness.py, 4 Turns)          | --> | (scans.db WAL Mode) |
+-----------------------------+-----------------------------+     +---------------------+
                              |
                              | 1. POST [https://api.browser.tinyfish.ai](https://api.browser.tinyfish.ai) (Get cdp_url)
                              | 2. Playwright connect_over_cdp(cdp_url)
                              | 3. Native CDP Listeners (Audits, Network) + DOM JS
                              | 4. DELETE /{session_id} (Guaranteed Teardown)
                              v
+-----------------------------------------------------------+
|            TinyFish Cloud Browser Infrastructure          |
+-----------------------------------------------------------+
```

---

## 📂 Repository Structure

```text
Tinyfah/
├── backend/
│   ├── main.py              # FastAPI endpoints, CORS middleware, BackgroundTasks trigger
│   ├── database.py          # SQLModel Scan table + SQLite WAL concurrency configuration
│   ├── scanner.py           # TinyFish session lifecycle manager & CDP event collector
│   ├── agent_harness.py     # Gemini 2.5 Flash ReAct loop, CDP tools, & Pydantic grader
│   ├── .env.example         # Environment variable template
│   └── pyproject.toml       # Python dependencies
└── frontend/                # Next.js dashboard (URL submission, live agent trace, report UI)
```

---

## 🚀 Getting Started & Setup Instructions

### Prerequisites
- **Python 3.11+** (Tested up to Python 3.14)
- **Node.js 18+** (for the Next.js frontend)
- **TinyFish API Key** (from [TinyFish Browser API](https://tinyfish.ai))
- **Google Gemini API Key** (from [Google AI Studio](https://aistudio.google.com/))

### 1. Backend Setup (`FastAPI`)

```bash
# Navigate to the backend directory
cd backend

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install fastapi uvicorn sqlmodel httpx playwright google-genai python-dotenv
```

Create a `.env` file in the `backend/` folder:

```env
TINYFISH_API_KEY=your_tinyfish_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
```

Start the FastAPI server:

```bash
uvicorn main:app --reload --port 8000
```
The API will be live at `http://localhost:8000` (Interactive Swagger docs at `http://localhost:8000/docs`).

### 2. Frontend Setup (`Next.js`)

```bash
# In a new terminal, navigate to the frontend directory
cd frontend

# Install packages and start the development server
npm install
npm run dev
```
Open `http://localhost:3000` in your browser to launch the Tinyfah dashboard.

---

## 🔌 API Reference

### 1. Start a New Vulnerability Scan
**`POST /scans`**
```json
{
  "url": "[https://example.com](https://example.com)",
  "focus_prompt": "Perform a full passive web vulnerability audit focusing on headers, cookies, and exposed globals."
}
```
**Response (`200 OK`):** Returns a `Scan` object immediately with `"status": "running"` and `"id": 1`.

### 2. Poll Scan Progress & Live Agent Trace
**`GET /scans/{scan_id}`**
Returns the current status (`running`, `completed`, or `failed`), live `agent_trace` steps, and—once completed—the full structured security report:
```json
{
  "id": 1,
  "url": "[https://example.com](https://example.com)",
  "status": "completed",
  "score": 75,
  "grade": "B",
  "results": {
    "summary": "The application enforces HTTPS but lacks a Content-Security-Policy and exposes session cookies without Secure/HttpOnly flags.",
    "findings": [
      {
        "severity": "medium",
        "category": "Headers",
        "title": "Missing Content-Security-Policy (CSP)",
        "evidence": "No content-security-policy header present in Document response.",
        "remediation": "Add a strict Content-Security-Policy header restricting script-src to trusted origins."
      }
    ],
    "agent_trace": [
      {
        "step": 1,
        "tool": "inspect_cookies_and_storage",
        "reason": "Initial recon completed; checking CDP cookie security flags and storage keys.",
        "observation_preview": "{\"cookies\": [], \"storage\": {\"localStorageKeyCount\": 0}}"
      }
    ]
  }
}
```

### 3. List Recent Scans
**`GET /scans`** — Returns the 20 most recent scans ordered by timestamp.

---

## 🛡️ Security & Ethics Notice
Tinyfah performs **strictly passive, non-destructive inspection** (evaluating HTTP headers, cookie flags, DOM attributes, Subresource Integrity tags, and client-side library versions). It does not transmit active exploit payloads or perform destructive fuzzing.
