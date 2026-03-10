package reporter

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
)

// GenerateHTMLReport generates an interactive HTML report to a file
func GenerateHTMLReport(filename string, findings []Finding, summary ReportSummary) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return GenerateHTMLReportToWriter(file, findings, summary)
}

// GenerateHTMLReportToWriter generates an interactive HTML report to any io.Writer
func GenerateHTMLReportToWriter(w io.Writer, findings []Finding, summary ReportSummary) error {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
		"confidencePct": func(c float64) string {
			return fmt.Sprintf("%.0f%%", c*100)
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"splitPrefix": func(s string) string {
			parts := strings.SplitN(s, ":", 2)
			return parts[0]
		},
		"splitDesc": func(s string) string {
			parts := strings.SplitN(s, ":", 2)
			if len(parts) > 1 {
				return parts[1]
			}
			return ""
		},
	}).Parse(htmlTemplate))

	confirmed, falsePositives := SplitFindings(findings)

	data := struct {
		Findings       []Finding
		FalsePositives []Finding
		Summary        ReportSummary
		RiskScore      RiskScore
		PriorityMatrix PriorityMatrix
		CWECounts      []KVCount
		OWASPCounts    []KVCount
	}{
		Findings:       confirmed,
		FalsePositives: falsePositives,
		Summary:        summary,
		RiskScore:      CalculateRiskScore(findings),
		PriorityMatrix: GetPriorityMatrix(findings),
		CWECounts:      aggregateCWE(findings),
		OWASPCounts:    aggregateOWASP(findings),
	}

	return tmpl.Execute(w, data)
}

// KVCount is a key-value pair for aggregated counts
type KVCount struct {
	Key   string
	Count int
}

func aggregateCWE(findings []Finding) []KVCount {
	counts := make(map[string]int)
	for _, f := range findings {
		if f.CWE != "" && f.CWE != "N/A" {
			counts[f.CWE]++
		}
	}
	var result []KVCount
	for k, v := range counts {
		result = append(result, KVCount{Key: k, Count: v})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	if len(result) > 15 {
		result = result[:15]
	}
	return result
}

func aggregateOWASP(findings []Finding) []KVCount {
	counts := make(map[string]int)
	for _, f := range findings {
		if f.OWASP != "" && f.OWASP != "N/A" {
			counts[f.OWASP]++
		}
	}
	var result []KVCount
	for k, v := range counts {
		result = append(result, KVCount{Key: k, Count: v})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	return result
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔒 Security Scan Report - {{.Summary.TargetDirectory}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1"></script>
    <style>
        :root {
            /* Light theme (Default) */
            --primary: #2563eb; --primary-dark: #1d4ed8; --primary-glow: rgba(37, 99, 235, 0.15);
            --critical: #dc2626; --high: #ea580c; --medium: #ca8a04; --low: #0284c7; --info: #4f46e5;
            --success: #16a34a;
            --bg: #f8fafc; --bg-card: #ffffff; --bg-hover: #f1f5f9;
            --text: #0f172a; --text-muted: #475569; --text-dim: #94a3b8;
            --border: #e2e8f0; --border-active: #94a3b8;
            --glass: rgba(255, 255, 255, 0.95); --glass-border: #e2e8f0;
            --shadow: 0 1px 3px 0 rgba(0,0,0,0.1), 0 1px 2px -1px rgba(0,0,0,0.1); 
            --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -4px rgba(0,0,0,0.1);
            --radius: 8px; --radius-sm: 6px;
        }
        [data-theme="dark"] {
            /* Dark theme */
            --primary: #3b82f6; --primary-dark: #60a5fa; --primary-glow: rgba(59, 130, 246, 0.2);
            --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #0ea5e9; --info: #8b5cf6;
            --success: #22c55e;
            --bg: #0f172a; --bg-card: #1e293b; --bg-hover: #334155;
            --text: #f8fafc; --text-muted: #cbd5e1; --text-dim: #8196b3ff;
            --border: #334155; --border-active: #475569;
            --glass: rgba(30, 41, 59, 0.95); --glass-border: #334155;
            --shadow: 0 4px 6px -1px rgba(0,0,0,0.3); --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.4);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 24px; min-height: 100vh; }
        .container { max-width: 1700px; margin: 0 auto; }

        /* === Header === */
        .header { background: var(--bg-card); padding: 32px 48px; border-radius: var(--radius); margin-bottom: 28px; border: 1px solid var(--border); box-shadow: var(--shadow); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 24px; position: relative; overflow: hidden; }
        .header h1 { font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; color: var(--text); }
        .header p { opacity: 0.8; font-size: 0.95rem; color: var(--text-muted); margin-top: 4px; }
        .header-actions { display: flex; gap: 10px; z-index: 1; }
        .btn { padding: 8px 16px; border-radius: var(--radius-sm); font-weight: 500; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; transition: all 0.2s; border: 1px solid var(--border); background: var(--bg); color: var(--text); font-family: inherit; font-size: 0.85rem; }
        .btn-primary { background: var(--primary); color: #fff; border-color: var(--primary); }
        .btn-primary:hover { background: var(--primary-dark); }
        .btn-outline { background: transparent; }
        .btn-outline:hover { background: var(--bg-hover); }

        /* === Risk Score === */
        .risk-section { display: grid; grid-template-columns: 340px 1fr; gap: 28px; margin-bottom: 28px; }
        .risk-card { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); padding: 36px; border-radius: var(--radius); box-shadow: var(--shadow); text-align: center; }
        .risk-ring { width: 180px; height: 180px; margin: 16px auto; position: relative; }
        .risk-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
        .risk-ring circle { fill: none; stroke-width: 10; stroke-linecap: round; }
        .risk-ring .bg { stroke: var(--border); }
        .risk-ring .fill { transition: stroke-dashoffset 1.5s ease; }
        .risk-value { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 2.8rem; font-weight: 800; }
        .risk-label { font-size: 1.1rem; color: var(--text-muted); margin-top: 8px; font-weight: 500; }

        /* === Stats === */
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 28px; }
        .stat-card { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); padding: 24px 20px; border-radius: var(--radius-sm); box-shadow: var(--shadow); text-align: center; position: relative; overflow: hidden; transition: all 0.3s; }
        .stat-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-lg); }
        .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }
        .stat-card.critical::before { background: var(--critical); }
        .stat-card.high::before { background: var(--high); }
        .stat-card.medium::before { background: var(--medium); }
        .stat-card.low::before { background: var(--low); }
        .stat-card.total::before { background: linear-gradient(90deg, var(--primary), var(--info)); }
        .stat-card.ai::before { background: var(--success); }
        .stat-value { font-size: 2.4rem; font-weight: 800; margin-bottom: 4px; }
        .stat-value.critical { color: var(--critical); }
        .stat-value.high { color: var(--high); }
        .stat-value.medium { color: var(--medium); }
        .stat-value.low { color: var(--low); }
        .stat-label { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }

        /* === Charts === */
        .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; margin-bottom: 28px; }
        .chart-card { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); padding: 28px; border-radius: var(--radius); box-shadow: var(--shadow); }
        .chart-card h3 { margin-bottom: 16px; font-weight: 700; font-size: 1.1rem; }
        .chart-wrap { height: 300px; position: relative; }

        /* === Priority Matrix === */
        .priority-section { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); padding: 32px; border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 28px; }
        .priority-section h2 { margin-bottom: 20px; font-weight: 700; }
        .priority-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
        .priority-card { padding: 24px; border-radius: var(--radius-sm); border: 1px solid var(--border); text-align: center; transition: all 0.3s; }
        .priority-card:hover { transform: translateY(-3px); }
        .priority-card.p0 { border-color: var(--critical); background: rgba(239,68,68,0.08); }
        .priority-card.p1 { border-color: var(--high); background: rgba(249,115,22,0.08); }
        .priority-card.p2 { border-color: var(--medium); background: rgba(234,179,8,0.08); }
        .priority-card.p3 { border-color: var(--low); background: rgba(6,182,212,0.08); }
        .priority-card h4 { font-size: 0.85rem; margin-bottom: 8px; font-weight: 600; }
        .priority-card .count { font-size: 2.4rem; font-weight: 800; }
        .priority-card .desc { color: var(--text-muted); font-size: 0.8rem; margin-top: 6px; }

        /* === CWE/OWASP === */
        .ref-section { margin-bottom: 28px; background: var(--bg-card); padding: 32px; border-radius: var(--radius); border: 1px solid var(--border); box-shadow: var(--shadow); }
        .ref-section h2 { margin-bottom: 20px; font-weight: 700; }
        .ref-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 32px; }
        @media (max-width: 768px) { .ref-grid { grid-template-columns: 1fr; } }
        .ref-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .ref-table th { text-align: left; padding: 8px; border-bottom: 2px solid var(--border); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; white-space: nowrap; }
        .ref-table td { padding: 10px 8px; border-bottom: 1px solid var(--border); }
        .ref-badge { border: 1px solid var(--border); border-radius: 4px; padding: 2px 6px; background: var(--bg-hover); font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; white-space: nowrap; }

        /* === Filters === */
        .filters { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); padding: 20px 24px; border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 20px; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
        .filters label { font-weight: 600; font-size: 0.9rem; color: var(--text-muted); }
        .filters input, .filters select { padding: 10px 14px; border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 0.9rem; min-width: 180px; background: var(--bg); color: var(--text); font-family: inherit; transition: border-color 0.3s; }
        .filters input:focus, .filters select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-glow); }
        .result-count { margin-left: auto; color: var(--text-dim); font-size: 0.85rem; font-weight: 500; }
        .pagination { display: flex; align-items: center; gap: 8px; margin-left: 16px; }
        .pagination button { padding: 8px 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); color: var(--text); cursor: pointer; font-family: inherit; font-weight: 500; transition: all 0.2s; }
        .pagination button:hover { border-color: var(--primary); background: rgba(99,102,241,0.1); }
        .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
        .pagination span { color: var(--text-muted); font-size: 0.85rem; }

        /* === Table === */
        .table-container { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; margin-bottom: 28px; }
        table { width: 100%; border-collapse: collapse; table-layout: auto; }
        thead { background: var(--bg); border-bottom: 1px solid var(--border); }
        th { padding: 12px 12px; text-align: left; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); cursor: pointer; user-select: none; white-space: nowrap; position: sticky; top: 0; z-index: 10; }
        th:hover { background: var(--bg-hover); color: var(--text); }
        th .sort-icon { margin-left: 4px; opacity: 0.5; font-size: 0.7rem; }
        td { padding: 12px; border-bottom: 1px solid var(--border); font-size: 0.88rem; vertical-align: top; }
        tr { transition: background 0.2s; }
        tr:hover { background: var(--bg-hover); }

        /* Resizable columns */
        th { resize: horizontal; overflow: hidden; min-width: 60px; }

        .severity-badge { display: inline-flex; align-items: center; padding: 5px 12px; border-radius: 20px; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .severity-badge.critical { background: rgba(239,68,68,0.15); color: #f87171; }
        .severity-badge.high { background: rgba(249,115,22,0.15); color: #fb923c; }
        .severity-badge.medium { background: rgba(234,179,8,0.15); color: #facc15; }
        .severity-badge.low { background: rgba(6,182,212,0.15); color: #22d3ee; }
        .severity-badge.info { background: rgba(139,92,246,0.15); color: #a78bfa; }

        .ai-badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 16px; font-weight: 500; font-size: 0.75rem; }
        .ai-badge.yes { background: rgba(34,197,94,0.15); color: #4ade80; }
        .ai-badge.no { background: rgba(239,68,68,0.15); color: #f87171; }
        .ai-badge.skipped { background: rgba(148,163,184,0.1); color: var(--text-dim); }

        .conf-bar { display: flex; align-items: center; gap: 6px; }
        .conf-fill { height: 6px; border-radius: 3px; min-width: 8px; }
        .conf-high { background: #22c55e; }
        .conf-med { background: #eab308; }
        .conf-low { background: #ef4444; }
        .conf-text { font-size: 0.78rem; color: var(--text-dim); font-family: 'JetBrains Mono', monospace; }

        .cell-file { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--text-muted); max-width: 280px; word-break: break-all; }
        .cell-desc { max-width: 360px; }
        .cell-desc.truncated { cursor: pointer; }
        .cell-desc.truncated::after { content: ' ▸ more'; color: var(--primary); font-weight: 500; font-size: 0.8rem; }

        /* Expandable Row Content */
        .expandable-content { display: none; padding: 20px; background: rgba(0,0,0,0.15); border-radius: 0 0 var(--radius-sm) var(--radius-sm); border-top: 1px solid var(--border); box-shadow: inset 0 2px 10px rgba(0,0,0,0.1); margin-top: -1px; }
        .row-expanded .expandable-content { display: block; animation: slideDown 0.3s ease; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .main-row { cursor: pointer; transition: background-color 0.2s; }
        .main-row:hover { background-color: var(--bg-hover); }
        .row-expanded .main-row { background-color: var(--bg-hover); border-bottom-color: transparent; }
        
        /* Code snippet styling */
        .code-block { background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; overflow-x: auto; white-space: pre; border: 1px solid #333; margin: 12px 0 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.2); }
        .detail-section { margin-bottom: 20px; }
        .detail-section h4 { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: 700; }
        .detail-text { font-size: 0.95rem; line-height: 1.6; }
        
        .toggle-icon { font-size: 1.2rem; transition: transform 0.3s; color: var(--primary); display: inline-block; width: 24px; text-align: center; }
        .row-expanded .toggle-icon { transform: rotate(90deg); }

        .source-badge { display: inline-flex; padding: 3px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .source-badge.ai { background: rgba(139,92,246,0.15); color: #a78bfa; }
        .source-badge.semgrep { background: rgba(34,197,94,0.15); color: #4ade80; }
        .source-badge.custom { background: rgba(99,102,241,0.15); color: #818cf8; }
        .source-badge.secret { background: rgba(249,115,22,0.15); color: #fb923c; }

        /* === Footer === */
        .footer { text-align: center; padding: 40px 20px; color: var(--text-dim); font-size: 0.85rem; margin-top: 20px; border-top: 1px solid var(--border); }

        @media (max-width: 1200px) { .risk-section { grid-template-columns: 1fr; } .charts-row { grid-template-columns: 1fr; } .ref-grid { grid-template-columns: 1fr; } .priority-grid { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 768px) { .header { flex-direction: column; text-align: center; } .filters { flex-direction: column; align-items: stretch; } .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        @media print { .header, .filters, .btn, .pagination { display: none !important; } }
    </style>
</head>
<body>
<div class="container" id="report-content">
    <div class="header">
        <div>
            <h1>🛡️ Security Scan Report</h1>
            <p><strong>Target:</strong> {{.Summary.TargetDirectory}}</p>
            <p><strong>Generated:</strong> {{.Summary.ScanDate}} &nbsp;|&nbsp; <strong>Version:</strong> v{{.Summary.ScannerVersion}}</p>
        </div>
        <div class="header-actions">
            <button class="btn btn-outline" onclick="toggleTheme()">🌓 Theme</button>
            <button class="btn btn-white" id="exportBtn" onclick="exportPDF()">📄 Export PDF</button>
        </div>
    </div>

    <!-- Risk Score + Summary -->
    <div class="risk-section">
        <div class="risk-card">
            <h3 style="color:var(--text-muted); font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:1px;">Security Score</h3>
            <div class="risk-ring">
                <svg viewBox="0 0 200 200">
                    <circle class="bg" cx="100" cy="100" r="85"/>
                    <circle class="fill" cx="100" cy="100" r="85"
                        stroke="{{if eq .RiskScore.Level "Critical Risk"}}#ef4444{{else if eq .RiskScore.Level "High Risk"}}#f97316{{else if eq .RiskScore.Level "Medium Risk"}}#eab308{{else}}#22c55e{{end}}"
                        stroke-dasharray="534" stroke-dashoffset="{{if eq .RiskScore.Score 0}}534{{else}}{{.RiskScore.Score}}{{end}}"/>
                </svg>
                <div class="risk-value" style="color:{{if eq .RiskScore.Level "Critical Risk"}}#ef4444{{else if eq .RiskScore.Level "High Risk"}}#f97316{{else if eq .RiskScore.Level "Medium Risk"}}#eab308{{else}}#22c55e{{end}}">{{.RiskScore.Score}}</div>
            </div>
            <div class="risk-label">{{.RiskScore.Level}}</div>
        </div>

        <div>
            <div class="stats-grid">
                <div class="stat-card total"><div class="stat-value">{{.Summary.TotalFindings}}</div><div class="stat-label">Total</div></div>
                <div class="stat-card critical"><div class="stat-value critical">{{.Summary.CriticalCount}}</div><div class="stat-label">Critical</div></div>
                <div class="stat-card high"><div class="stat-value high">{{.Summary.HighCount}}</div><div class="stat-label">High</div></div>
                <div class="stat-card medium"><div class="stat-value medium">{{.Summary.MediumCount}}</div><div class="stat-label">Medium</div></div>
                <div class="stat-card low"><div class="stat-value low">{{.Summary.LowCount}}</div><div class="stat-label">Low</div></div>
                <div class="stat-card ai"><div class="stat-value" style="color:var(--success)">{{.Summary.AIValidatedCount}}</div><div class="stat-label">AI Valid.</div></div>
            </div>

            <!-- Priority Matrix -->
            <div class="priority-grid" style="margin-top:8px;">
                <div class="priority-card p0"><h4>🔴 P0 — Immediate</h4><div class="count" style="color:var(--critical)">{{len .PriorityMatrix.P0}}</div><div class="desc">Critical, AI confirmed</div></div>
                <div class="priority-card p1"><h4>🟠 P1 — This Sprint</h4><div class="count" style="color:var(--high)">{{len .PriorityMatrix.P1}}</div><div class="desc">High priority</div></div>
                <div class="priority-card p2"><h4>🟡 P2 — Next Sprint</h4><div class="count" style="color:var(--medium)">{{len .PriorityMatrix.P2}}</div><div class="desc">Medium priority</div></div>
                <div class="priority-card p3"><h4>🟢 P3 — Backlog</h4><div class="count" style="color:var(--low)">{{len .PriorityMatrix.P3}}</div><div class="desc">Low priority</div></div>
            </div>
        </div>
    </div>

    <!-- Charts -->
    <div class="charts-row">
        <div class="chart-card">
            <h3>📊 Severity Distribution</h3>
            <div class="chart-wrap"><canvas id="severityChart"></canvas></div>
        </div>
        <div class="chart-card">
            <h3>📈 Top CWE Categories</h3>
            <div class="chart-wrap"><canvas id="cweChart"></canvas></div>
        </div>
    </div>

    <!-- CWE/OWASP Cross-Reference -->
    <div class="ref-section">
        <h2>📋 CWE / OWASP Top 10 Cross-Reference</h2>
        <div class="ref-grid" style="margin-top: 20px;">
            <div style="overflow-x: auto;">
                <h4 style="margin-bottom: 12px; color: var(--text-muted); font-size:0.85rem; text-transform:uppercase; letter-spacing:1px;">Top CWE Categories</h4>
                <table class="ref-table">
                    <thead><tr><th>CWE ID</th><th>Count</th></tr></thead>
                    <tbody>
                    {{range .CWECounts}}
                    <tr><td style="white-space: nowrap;"><span class="ref-badge">{{splitPrefix .Key}}</span><span style="font-size: 0.85rem; color: var(--text-muted); margin-left: 8px;">{{splitDesc .Key}}</span></td><td><strong>{{.Count}}</strong></td></tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
            <div style="overflow-x: auto;">
                <h4 style="margin-bottom: 12px; color: var(--text-muted); font-size:0.85rem; text-transform:uppercase; letter-spacing:1px;">OWASP Top 10 Mapping</h4>
                <table class="ref-table">
                    <thead><tr><th>Category</th><th>Count</th></tr></thead>
                    <tbody>
                    {{range .OWASPCounts}}
                    <tr><td style="white-space: nowrap;"><span class="ref-badge">{{splitPrefix .Key}}</span><span style="font-size: 0.85rem; color: var(--text-muted); margin-left: 8px;">{{splitDesc .Key}}</span></td><td><strong>{{.Count}}</strong></td></tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Filters -->
    <div class="filters">
        <label>🔍 Filter:</label>
        <input type="text" id="searchInput" placeholder="Search issues, files, CWE..." oninput="filterAndPaginate()">
        <select id="severityFilter" onchange="filterAndPaginate()">
            <option value="">All Severities</option>
            <option value="critical">🔴 Critical</option>
            <option value="high">🟠 High</option>
            <option value="medium">🟡 Medium</option>
            <option value="low">🔵 Low</option>
            <option value="info">🟣 Info</option>
        </select>
        <select id="sourceFilter" onchange="filterAndPaginate()">
            <option value="">All Sources</option>
            <option value="ai">🧠 AI Discovery</option>
            <option value="semgrep">🔎 Semgrep</option>
            <option value="custom">📋 Custom Rules</option>
            <option value="secret">🔑 Secret Detection</option>
        </select>
        <span class="result-count" id="resultCount"></span>
        <div class="pagination">
            <button onclick="prevPage()" id="prevBtn">◀ Prev</button>
            <span id="pageInfo">1 / 1</span>
            <button onclick="nextPage()" id="nextBtn">Next ▶</button>
        </div>
    </div>

    <!-- Findings Table -->
    <div class="table-container">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)"># <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(1)">Issue <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(2)">File Path <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(3)">Severity <span class="sort-icon">⇅</span></th>
                    <th>Conf.</th>
                    <th onclick="sortTable(5)">CWE <span class="sort-icon">⇅</span></th>
                    <th>Source</th>
                    <th>AI</th>
                    <th onclick="sortTable(8)">Description <span class="sort-icon">⇅</span></th>
                    <th>Fix</th>
                </tr>
            </thead>
            {{range .Findings}}
            <tbody class="finding-group">
                <tr class="main-row" data-severity="{{.Severity}}" data-source="{{.Source}}" onclick="toggleRow(this)">
                    <td style="font-weight: 700; color: var(--text-muted);"><span class="toggle-icon">▸</span> {{.SrNo}}</td>
                    <td style="font-weight: 600;">{{.IssueName}}</td>
                    <td class="cell-file" title="{{.FilePath}}">{{.FilePath}}:{{.LineNumber}}</td>
                    <td><span class="severity-badge {{.Severity}}">{{.Severity}}</span></td>
                    <td>
                        <div class="conf-bar" title="AI Confidence: {{confidencePct .Confidence}}">
                            <span class="conf-fill {{if ge .Confidence 0.8}}conf-high{{else if ge .Confidence 0.5}}conf-med{{else}}conf-low{{end}}" style="width: {{confidencePct .Confidence}};"></span>
                        </div>
                    </td>
                    <td>{{if .CWE}}<span class="ref-badge">{{.CWE}}</span>{{end}}</td>
                    <td>
                        {{if contains .Source "ai"}}<span class="source-badge ai">AI</span>
                        {{else if contains .Source "semgrep"}}<span class="source-badge semgrep">Semgrep</span>
                        {{else if contains .Source "taint"}}<span class="source-badge custom">Taint</span>
                        {{else if contains .Source "ast"}}<span class="source-badge custom">AST</span>
                        {{else if contains .Source "secret"}}<span class="source-badge secret">Secret</span>
                        {{else}}<span class="source-badge custom">Rules</span>{{end}}
                    </td>
                    <td style="text-align: center;">
                        {{if eq .AiValidated "Yes"}}<span class="ai-badge yes" title="AI Validated">✅</span>
                        {{else if contains .AiValidated "Discovered"}}<span class="ai-badge yes" title="AI Discovered">🧠</span>
                        {{else if eq .AiValidated "No"}}<span class="ai-badge no" title="False Positive">❌</span>
                        {{else}}<span class="ai-badge skipped" title="Not Checked">—</span>{{end}}
                    </td>
                    <td class="cell-desc">{{truncate .Description 80}}</td>
                    <td class="cell-desc">{{truncate .Remediation 60}}</td>
                </tr>
                <tr class="detail-row" data-severity="{{.Severity}}" data-source="{{.Source}}" style="display: none;">
                    <td colspan="10" style="padding: 0; border-bottom: none;">
                        <div class="expandable-content">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 32px;">
                                <div>
                                    <div class="detail-section">
                                        <h4>Full Description</h4>
                                        <div class="detail-text">{{.Description}}</div>
                                    </div>
                                    
                                    <div class="detail-section">
                                        <h4>Remediation</h4>
                                        <div class="detail-text">{{.Remediation}}</div>
                                    </div>
                                    
                                    {{if .ExploitPoC}}
                                    <div class="detail-section">
                                        <h4>🔥 AI-Generated Exploit PoC</h4>
                                        <div class="code-block" style="border-color: rgba(239, 68, 68, 0.4);"><pre>{{.ExploitPoC}}</pre></div>
                                    </div>
                                    {{end}}

                                    {{if .FixedCode}}
                                    <div class="detail-section">
                                        <h4>✨ AI-Suggested Secure Code</h4>
                                        <div class="code-block" style="border-left: 4px solid #4ade80; background: rgba(34, 197, 94, 0.05); color: #d4d4d4;"><pre>{{.FixedCode}}</pre></div>
                                    </div>
                                    {{end}}
                                </div>
                                
                                <div>
                                    {{if .CodeSnippet}}
                                    <div class="detail-section">
                                        <h4>📄 Vulnerable Code Snippet</h4>
                                        <div class="code-block"><pre>{{.CodeSnippet}}</pre></div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                        </div>
                    </td>
                </tr>
            </tbody>
            {{end}}
        </table>
    </div>

    <!-- False Positives Manual Review Section -->
    {{if .FalsePositives}}
    <div style="margin-top: 40px; padding: 28px; background: linear-gradient(135deg, rgba(234,179,8,0.08) 0%, rgba(239,68,68,0.05) 100%); border: 1px solid rgba(234,179,8,0.3); border-radius: var(--radius); box-shadow: var(--shadow);">
        <h2 style="color: #facc15; margin-bottom: 8px; font-size: 1.4rem;">⚠️ Manual Review — Potential False Positives ({{len .FalsePositives}})</h2>
        <p style="color: var(--text-muted); margin-bottom: 20px; font-size: 0.9rem;">
            The following findings were flagged as <strong>potential false positives</strong> by the AI validator.
            They are listed separately for manual review by a security engineer.
        </p>
        <div class="table-container" style="margin-top: 16px;">
            <table id="fpTable">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Issue</th>
                        <th>File Path</th>
                        <th>Severity</th>
                        <th>CWE</th>
                        <th>AI Reason</th>
                    </tr>
                </thead>
                {{range .FalsePositives}}
                <tbody class="finding-group">
                    <tr class="main-row" data-severity="{{.Severity}}" data-source="{{.Source}}" onclick="toggleRow(this)">
                        <td style="font-weight: 700; color: var(--text-muted);"><span class="toggle-icon">▸</span> {{.SrNo}}</td>
                        <td style="font-weight: 600;">{{.IssueName}}</td>
                        <td class="cell-file" title="{{.FilePath}}">{{.FilePath}}:{{.LineNumber}}</td>
                        <td><span class="severity-badge {{.Severity}}">{{.Severity}}</span></td>
                        <td>{{if .CWE}}<span class="ref-badge">{{.CWE}}</span>{{end}}</td>
                        <td class="cell-desc">{{truncate .Description 80}}</td>
                    </tr>
                    <tr class="detail-row" data-severity="{{.Severity}}" data-source="{{.Source}}" style="display: none;">
                        <td colspan="6" style="padding: 0; border-bottom: none;">
                            <div class="expandable-content">
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 32px;">
                                    <div>
                                        <div class="detail-section">
                                            <h4>AI False Positive Explanation</h4>
                                            <div class="detail-text">{{.Description}}</div>
                                        </div>
                                        <div class="detail-section">
                                            <h4>Original Remediation</h4>
                                            <div class="detail-text">{{.Remediation}}</div>
                                        </div>
                                    </div>
                                    <div>
                                        {{if .CodeSnippet}}
                                        <div class="detail-section">
                                            <h4>📄 Code Snippet</h4>
                                            <div class="code-block"><pre>{{.CodeSnippet}}</pre></div>
                                        </div>
                                        {{end}}
                                    </div>
                                </div>
                            </div>
                        </td>
                    </tr>
                </tbody>
                {{end}}
            </table>
        </div>
    </div>
    {{end}}

    <div class="footer">
        <p><strong>Generated by AI-Powered Source Code Scanner v{{.Summary.ScannerVersion}}</strong></p>
        <p style="margin-top:8px;">{{.Summary.TotalFindings}} findings • {{.Summary.CriticalCount}} critical • {{.Summary.HighCount}} high • {{.Summary.MediumCount}} medium • {{.Summary.LowCount}} low</p>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
<script>
    // Theme toggle
    // document.documentElement.setAttribute('data-theme', 'dark');
    function toggleTheme() {
        const html = document.documentElement;
        html.setAttribute('data-theme', html.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
    }

    // Charts
    const chartColors = { bg: 'transparent', text: '#94a3b8', grid: 'rgba(148,163,184,0.1)' };

    new Chart(document.getElementById('severityChart'), {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [{{.Summary.CriticalCount}}, {{.Summary.HighCount}}, {{.Summary.MediumCount}}, {{.Summary.LowCount}}, {{.Summary.InfoCount}}],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#06b6d4', '#8b5cf6'],
                borderWidth: 0, spacing: 3, borderRadius: 4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { padding: 16, usePointStyle: true, pointStyle: 'circle', color: chartColors.text, font: { family: 'Inter', size: 12 } } }
            },
            cutout: '65%'
        }
    });

    // CWE bar chart
    const cweLabels = [{{range .CWECounts}}'{{.Key}}',{{end}}];
    const cweCounts = [{{range .CWECounts}}{{.Count}},{{end}}];
    new Chart(document.getElementById('cweChart'), {
        type: 'bar',
        data: {
            labels: cweLabels,
            datasets: [{ data: cweCounts, backgroundColor: '#6366f1', borderRadius: 6, barThickness: 24 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: chartColors.grid }, ticks: { color: chartColors.text } },
                y: { grid: { display: false }, ticks: { color: chartColors.text, font: { family: 'JetBrains Mono', size: 11 } } }
            }
        }
    });

    // Pagination & Filtering
    const PAGE_SIZE = 50;
    let currentPage = 1;
    let filteredRows = [];

    function getVisibleRows() {
        // Now selecting the finding-group tbodys instead of individual rows
        const groups = Array.from(document.querySelectorAll('#findingsTable .finding-group'));
        const search = document.getElementById('searchInput').value.toLowerCase();
        const severity = document.getElementById('severityFilter').value;
        const source = document.getElementById('sourceFilter').value;

        return groups.filter(group => {
            const mainRow = group.querySelector('.main-row');
            if (!mainRow) return false;
            
            // Search text from both main row and detail row
            const text = group.textContent.toLowerCase();
            const sev = mainRow.getAttribute('data-severity') || '';
            const src = mainRow.getAttribute('data-source') || '';
            
            return (!search || text.includes(search)) &&
                   (!severity || sev === severity) &&
                   (!source || src.includes(source));
        });
    }

    function toggleRow(row) {
        const tbody = row.closest('tbody');
        const isExpanded = tbody.classList.contains('row-expanded');
        
        // Close all others (accordion style) - Optional, remove if you want multiple open
        // document.querySelectorAll('.finding-group.row-expanded').forEach(el => {
        //     if (el !== tbody) {
        //         el.classList.remove('row-expanded');
        //         el.querySelector('.detail-row').style.display = 'none';
        //     }
        // });

        if (isExpanded) {
            tbody.classList.remove('row-expanded');
            setTimeout(() => {
                if (!tbody.classList.contains('row-expanded')) {
                    row.nextElementSibling.style.display = 'none';
                }
            }, 300); // match animation duration
        } else {
            row.nextElementSibling.style.display = '';
            // small delay to allow display block to apply before adding animation class
            requestAnimationFrame(() => {
                tbody.classList.add('row-expanded');
            });
        }
    }

    function filterAndPaginate() {
        currentPage = 1;
        filteredRows = getVisibleRows();
        renderPage();
    }

    function renderPage() {
        const allGroups = document.querySelectorAll('#findingsTable .finding-group');
        allGroups.forEach(g => g.style.display = 'none');

        const start = (currentPage - 1) * PAGE_SIZE;
        const end = Math.min(start + PAGE_SIZE, filteredRows.length);
        const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));

        for (let i = start; i < end; i++) {
            filteredRows[i].style.display = '';
        }

        document.getElementById('resultCount').textContent = filteredRows.length + ' of ' + allGroups.length + ' findings';
        document.getElementById('pageInfo').textContent = currentPage + ' / ' + totalPages;
        document.getElementById('prevBtn').disabled = currentPage <= 1;
        document.getElementById('nextBtn').disabled = currentPage >= totalPages;
    }

    function prevPage() { if (currentPage > 1) { currentPage--; renderPage(); } }
    function nextPage() { const tp = Math.ceil(filteredRows.length / PAGE_SIZE); if (currentPage < tp) { currentPage++; renderPage(); } }

    // Sorting
    let sortCol = -1, sortAsc = true;
    function sortTable(col) {
        if (sortCol === col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
        const table = document.querySelector('#findingsTable');
        const groups = Array.from(table.querySelectorAll('.finding-group'));

        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        groups.sort((a, b) => {
            const rowA = a.querySelector('.main-row');
            const rowB = b.querySelector('.main-row');
            if (!rowA || !rowB) return 0;
            
            let va = rowA.cells[col]?.textContent.trim() || '';
            let vb = rowB.cells[col]?.textContent.trim() || '';
            
            if (col === 3) { va = sevOrder[va.toLowerCase()] ?? 5; vb = sevOrder[vb.toLowerCase()] ?? 5; }
            else if (col === 0 || col === 6) { va = parseInt(va.replace(/[^0-9]/g, '')) || 0; vb = parseInt(vb.replace(/[^0-9]/g, '')) || 0; }
            
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
        });
        groups.forEach(g => table.appendChild(g));
        filterAndPaginate();
    }

    // PDF Export
    async function exportPDF() {
        const btn = document.getElementById('exportBtn');
        btn.disabled = true; btn.innerHTML = '⏳ Generating...';
        try {
            await html2pdf().set({
                margin: [0.4, 0.4], filename: 'security-report.pdf',
                image: { type: 'jpeg', quality: 0.95 },
                html2canvas: { scale: 2, useCORS: true },
                jsPDF: { unit: 'in', format: 'letter', orientation: 'landscape' },
                pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
            }).from(document.querySelector('.container')).save();
            btn.innerHTML = '✅ Downloaded!';
        } catch(e) { alert('PDF export failed'); }
        setTimeout(() => { btn.disabled = false; btn.innerHTML = '📄 Export PDF'; }, 2000);
    }

    // Init
    document.addEventListener('DOMContentLoaded', () => { filterAndPaginate(); });

    // Risk ring animation
    setTimeout(() => {
        const fill = document.querySelector('.risk-ring .fill');
        if (fill) {
            const score = {{.RiskScore.Score}};
            const offset = 534 - (534 * score / 100);
            fill.style.strokeDashoffset = offset;
        }
    }, 300);
</script>
</body>
</html>`
