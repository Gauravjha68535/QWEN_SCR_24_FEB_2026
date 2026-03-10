# 🛡️ AI-Powered Security Scanner

> **Modern SAST & Supply Chain Security Platform**
> A high-performance, local-first security tool designed for modern engineering teams. Powered by Go and Local AI (Ollama).

This tool scans your codebase for security vulnerabilities, checks your external libraries for known CVEs, and uses AI to filter out false alarms and suggest actual code fixes—all running 100% locally on your machine.

---

## 🌟 What Can It Do? (Core Features Explained)

The scanner runs through several advanced phases to ensure your code is secure. Here is what each part does in simple terms:

| Feature | What it means & why it's useful |
| :--- | :--- |
| **🔍 Pattern Matching Engine** | Uses **928 security rules** across 20+ languages and 11 frameworks to instantly find dangerous code patterns (like hardcoded passwords, weak encryption, or SQL injection flaws). |
| **🧹 Contextual Filtering** | Automatically **skips test/mock/fixture files** and **strips comments** before scanning, so you don't get false alarms from commented-out code or test data. |
| **🌊 Enhanced Taint Analysis** | Tracks data flow with **variable alias tracking** and **scope-aware taint clearing**. If user input is assigned to a new variable, the taint follows it. Crossing a function boundary resets taint to prevent cross-function false positives. |
| **📦 Supply Chain (SCA)** | Integrates the official **Google OSV-Scanner CLI** for deep, accurate lockfile scanning (`package-lock.json`, `yarn.lock`, `go.sum`, `pom.xml`, etc.). If the CLI isn't installed, it falls back to our built-in parser + **OSV.dev API**. |
| **🔗 Reachability Analysis** | Builds a map of how your functions call each other. If it finds a vulnerability in a function that is *never actually called* by your app, it downgrades the severity to reduce noise! |
| **🤖 Local AI Validation** | Uses local AI (via Ollama) to look at the flagged code context and decide: *"Is this a real vulnerability or just a test file / safe configuration?"* This drastically reduces false positives. |
| **📊 Visual Web Dashboard** | Launches a local website showing beautiful, interactive charts of your security posture. |
| **🪄 Auto-Remediation** | Inside the Web Dashboard, you can click "**Get AI Fix**" to instantly generate a diff (before/after code snippet) showing exactly how to fix the vulnerability! |

---

## 🏁 How to Use (Beginner's Guide)

Follow these simple steps to install and run the scanner.

### Step 1: Prerequisites
Before using this tool, you need two things installed on your computer:
1. **Go (Golang)**: The programming language this tool is built with.
   - Download and install from [golang.org](https://go.dev/dl/).
2. **Ollama**: The local AI engine used to analyze code and generate fixes.
   - Download and install from [ollama.com](https://ollama.com/download).
3. **OSV-Scanner (Recommended)**: For accurate supply chain scanning, install Google's official CLI tool.
   - Run `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2`.

### Step 2: Download an AI Model
Once Ollama is installed, you need to download a "model" for it to use. Open your terminal or command prompt and run:
```bash
ollama run deepseek-coder:6.7b
```
*(Note: If you have less than 8GB of RAM, you might want to try a smaller model like `phi3:mini` or `qwen2.5-coder:1.5b` instead.)*

### Step 3: Run the Scanner interactively
Navigate to the directory where you downloaded this project in your terminal:
```bash
cd /path/to/this/project
```

Then, start the interactive scanner menu:
```bash
go run ./cmd/scanner
```

---

## ⚙️ Configuring Your Scan (The Interactive Menu)

When you run the command above, you will see a text-based menu. You configure your scan by typing numbers and pressing Enter. Here is how to set up the best scan:

1. **Set Target Directory**: Press `1` and enter the full path to the code you want to scan (e.g., `/home/user/my-app`).
2. **Enable Supply Chain Security**: Press `4` to turn this `ON`. If `osv-scanner` is installed, it uses Google's official CLI for deep lockfile scanning. Otherwise, it falls back to the built-in OSV.dev API.
3. **Enable Pattern Engine**: Make sure this is `ON` (Option `5`). The engine now strips comments and skips test files automatically.
4. **Enable Taint Analysis**: Make sure this is `ON` (Option `6`).
5. **Enable AI Validation**: Press `9` to turn this `ON` so the AI can filter out false alarms.
   - Press `13` to type in the name of the AI model you downloaded (e.g., `deepseek-coder:6.7b`).
6. **Enable Web Dashboard API**: Press `11` to turn this `ON`. This ensures the beautiful visual dashboard launches when the scan finishes.
7. **Start Scan**: Press `16` to begin!

*(Pro tip: The interactive menu remembers your choices for the next time you run it!)*

---

## 📈 Understanding the Output

Once the scan finishes, the tool provides results in multiple ways:

### 1. The Web Dashboard (Recommended)
If you enabled the Web Dashboard (Option 11), your browser will automatically open to `http://localhost:8080`.
- **Charts & Graphs**: View interactive pie charts of your severity levels and top vulnerability types.
- **Auto-Fixing**: Click on any vulnerability to see the exact code, and click **"Generate AI Fix"** to see a side-by-side diff of how to secure the code!

### 2. Static Reports
Look inside the folder where you ran the tool. You will find:
- **`report.html`**: A static, standalone HTML file you can share with your team.
- **`report.pdf`**: A clean document perfect for management and compliance records.
- **`report.csv`**: A raw spreadsheet of all findings for easy tracking.

---

## 📂 Project Structure (For Developers)

- **[`scanner/`](./scanner)**: Contains all the heavy lifting:
  - `pattern_engine.go` — Rule-based regex matching with **contextual filtering** (comment stripping, test-file skipping).
  - `taint-analyzer.go` — Enhanced source-to-sink data flow tracking with **alias propagation** and **scope boundaries**.
  - `osv_cli.go` — Google OSV-Scanner CLI integration for **supply chain analysis**.
  - `osv_client.go` — Fallback OSV.dev HTTP API client.
  - `dependency_scanner.go` — Orchestrator that auto-selects CLI or fallback SCA.
  - `helpers.go` — Shared utilities (`countLines`, `formatLineRef`, `StripComments`, `IsTestFile`, etc.).
  - `ast-analyzer.go` — Tree-sitter AST-based analysis for Python, JS/TS, Java, Kotlin.
  - `secret_detector.go` — Entropy-based hardcoded secret detection.
  - `reachability.go` — Call-graph reachability analysis.
- **[`rules/`](./rules)**: 928+ YAML security rules across 20+ languages and 11 frameworks.
- **[`ai/`](./ai)**: Connects to Ollama for AI-powered vulnerability validation and auto-fix generation.
- **[`cmd/scanner/`](./cmd/scanner)**: Entry point, interactive menu, and Local Web Dashboard Server.
- **[`reporter/`](./reporter)**: PDF, CSV, and HTML report generation with OWASP/CWE compliance mapping.

---

## 🧠 How False Positives Are Reduced

This scanner uses a **multi-layered** approach to minimize noise:

1. **Contextual Filtering** — Test files, mock directories, and fixture data are automatically excluded. Comments are stripped before pattern matching.
2. **Taint Scope Tracking** — Taint state is cleared at function/class boundaries, preventing cross-function false alarms.
3. **Reachability Analysis** — Vulnerabilities in unreachable (dead) code are downgraded.
4. **AI Validation** — A local LLM reviews each finding in context and marks false positives.
5. **Confidence Scoring** — Each finding has a confidence score (0.0–1.0) based on proximity, entropy, and detection method.