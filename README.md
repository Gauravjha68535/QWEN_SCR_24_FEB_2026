# 🛡️ AI-Powered Security Scanner

> **Modern SAST, Supply Chain, & AI-Orchestrated Security Platform**
> A high-performance, local-first security tool designed for elite engineering teams. Powered by Go and Local AI (Ollama).

This tool transforms security scanning from simple pattern matching into **Intelligent Orchestration**. It runs your codebase through 900+ static rules, performs AI-driven vulnerability discovery, and uses a "Security Guru" LLM to deduplicate and validate findings—all running 100% locally on your machine.

---

## 🌟 What Can It Do? (Core Features Explained)

| Feature | What it means & why it's useful |
| :--- | :--- |
| **🔍 Pattern Matching Engine** | Uses **928 security rules** across 20+ languages to find hardcoded secrets, weak crypto, and classic injections. |
| **🧠 Security Guru 3.0 (AI)** | **Chain of Thought (CoT)** reasoning. The AI "thinks" like an attacker, performing simulated **Taint-Flow** traces and construction exploitation payloads before reporting. |
| **🔄 Intelligent Orchestration** | **The Merger Mode:** Runs Static rules first, then AI Discovery, then uses a Master LLM to semantically deduplicate and merge the results into one "Master" report. |
| **🌊 Deep Flow Analysis** | Tracks data from Source to Sink. It understands what is MISSING—detecting the **Absence of CSRF tokens**, missing **HSTS/CSP headers**, or unvalidated entry points. |
| **📦 Supply Chain (SCA)** | Integrates **Google OSV-Scanner** for deep lockfile analysis. If the CLI is missing, it fails back to a custom built-in parser with OSV.dev API support. |
| **🛡️ Adversarial Validation** | The AI doesn't just "check" code; it attempts to **Simulated Bypass**. It tries to break your filters using encoding tricks (Base64, Unicode, Null bytes) to ensure they are truly secure. |

---

## 🏁 How to Use (Quick Start)

### Step 1: Prerequisites
1. **Go (Golang)**: [Download here](https://go.dev/dl/).
2. **Ollama**: [Download here](https://ollama.com/download).
3. **OSV-Scanner**: `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2` (Optional but recommended).

### Step 2: Download the "Guru" Model
Open your terminal and run:
```bash
ollama run qwen2.5-coder:7b  # Or deepseek-coder:6.7b
```

### Step 3: Run the Scanner
```bash
go run ./cmd/scanner
```

---

## ⚙️ The Elite AI Menu (Option 2)

We have upgraded the scan pipeline with 6 distinct modes:

1. **AI Validation Only**: Takes static findings and asks AI if they are real.
2. **AI Discovery Only**: AI hunts for vulnerabilities the static rules might miss.
3. **AI Discovery + Validate**: Find new issues AND double-check all of them.
4. **Static + AI + Validate**: The "Everything" mode. Sequential and thorough.
5. **Consolidated AI + Static**: **(Recommended)** Runs both, stashes results in a local DB, and merges them semantically into one clean report.
6. **Disable AI**: Standard static scanning only.

---

## 📂 Project Structure

- **[`ai/`](./ai)**: 
  - `discovery_scanner.go` — The "Guru" prompt with CoT and Taint-Flow simulation.
  - `validator.go` — Adversarial bypass simulation engine.
  - `merging_engine.go` — Semantic deduplication and finding correlation.
- **[`scanner/`](./scanner)**: Pattern-matching engine, AST analyzer, and SCA logic.
- **[`reporter/`](./reporter)**: Generates HTML, PDF, and CSV reports with Risk Scoring.
- **[`rules/`](./rules)**: 928+ YAML security rules.

---

## 🚿 How False Positives Are Killed
1. **Context Filtering:** Automatically ignores comments and test/mock files.
2. **Adversarial Bypass Sim:** The AI tries to "hack" the fix to ensure it works.
3. **Taint-Flow Simulation:** AI traces the path of data from request to database.
4. **Local DB Stashing:** Intermediate results are saved to `.findings_stashed.json` to prevent data loss.