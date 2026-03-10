package main

import (
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	dashboardFindings []reporter.Finding
	findingsMutex     sync.RWMutex
	startTime         time.Time
)

// StartWebDashboard starts a local HTTP server to serve the interactive report and API
func StartWebDashboard(port int) {
	mux := http.NewServeMux()

	// 1. Serve the live HTML Dashboard
	mux.HandleFunc("/", serveDashboardHTML)

	// 2. REST API endpoints
	mux.HandleFunc("/api/findings", handleGetFindings)
	mux.HandleFunc("/api/summary", handleGetSummary)

	// 3. Status/Health endpoint
	mux.HandleFunc("/api/status", handleGetStatus)

	// 4. Chart Data endpoint
	mux.HandleFunc("/api/charts", handleGetChartData)

	// 5. Auto-Fix endpoint
	mux.HandleFunc("/api/fix", handleGetFix)

	addr := fmt.Sprintf("localhost:%d", port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	utils.LogInfo(fmt.Sprintf("🌐 Web Dashboard starting on http://%s", addr))

	// Open the browser automatically
	go openBrowser("http://" + addr)

	// Start server (blocking)
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		utils.LogError("Dashboard server failed", err)
	}
}

// UpdateDashboardFindings is called by the main scanner process to push new findings
func UpdateDashboardFindings(newFindings []reporter.Finding) {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()

	// Replace completely. The slice is already deduped.
	dashboardFindings = make([]reporter.Finding, len(newFindings))
	copy(dashboardFindings, newFindings)
}

func serveDashboardHTML(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	findingsMutex.RLock()
	findings := make([]reporter.Finding, len(dashboardFindings))
	copy(findings, dashboardFindings)
	findingsMutex.RUnlock()

	// Generate fresh HTML report into a buffer (no disk I/O)
	summary := reporter.GenerateReportSummary(findings, ".")
	var buf bytes.Buffer
	err := reporter.GenerateHTMLReportToWriter(&buf, findings, summary)
	if err != nil {
		http.Error(w, "Failed to generate report HTML", http.StatusInternalServerError)
		return
	}

	// Inject Chart.js Dashboard before closing </body>
	htmlContent := buf.String()
	chartDashboard := generateChartDashboardHTML(findings)
	htmlContent = strings.Replace(htmlContent, "</body>", chartDashboard+"</body>", 1)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlContent))
}

func handleGetFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	findingsMutex.RLock()
	defer findingsMutex.RUnlock()

	// Basic filtering support via query params (e.g., ?severity=critical)
	severityFilter := r.URL.Query().Get("severity")

	var filtered []reporter.Finding
	if severityFilter != "" {
		for _, f := range dashboardFindings {
			if f.Severity == severityFilter {
				filtered = append(filtered, f)
			}
		}
	} else {
		filtered = dashboardFindings
	}

	json.NewEncoder(w).Encode(filtered)
}

func handleGetSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	findingsMutex.RLock()
	defer findingsMutex.RUnlock()

	summary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"total":    len(dashboardFindings),
	}

	for _, f := range dashboardFindings {
		summary[f.Severity]++
	}

	json.NewEncoder(w).Encode(summary)
}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]interface{}{
		"status": "running",
		"uptime": time.Since(startTime).String(),
		"memory": getMemoryStats(),
	}

	json.NewEncoder(w).Encode(status)
}

// handleGetChartData returns structured chart data for the dashboard
func handleGetChartData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	findingsMutex.RLock()
	defer findingsMutex.RUnlock()

	// Severity distribution
	severityDist := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	// CWE distribution (top 10)
	cweDist := make(map[string]int)
	// Findings by file (top 10)
	fileDist := make(map[string]int)
	// Source distribution
	sourceDist := make(map[string]int)

	for _, f := range dashboardFindings {
		severityDist[f.Severity]++
		if f.CWE != "" {
			cweDist[f.CWE]++
		}
		fileDist[f.FilePath]++
		if f.Source != "" {
			sourceDist[f.Source]++
		}
	}

	// Sort and take top 10 CWEs
	type kv struct {
		Key   string
		Value int
	}
	topCWEs := sortMapTopN(cweDist, 10)
	topFiles := sortMapTopN(fileDist, 10)

	chartData := map[string]interface{}{
		"severity":  severityDist,
		"top_cwes":  topCWEs,
		"top_files": topFiles,
		"sources":   sourceDist,
		"total":     len(dashboardFindings),
	}

	json.NewEncoder(w).Encode(chartData)
}

// handleGetFix returns the AI-suggested fix for a finding by ID
func handleGetFix(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, `{"error":"missing id parameter"}`, http.StatusBadRequest)
		return
	}

	var findingID int
	fmt.Sscanf(idStr, "%d", &findingID)

	findingsMutex.RLock()
	defer findingsMutex.RUnlock()

	for _, f := range dashboardFindings {
		if f.SrNo == findingID {
			fix := map[string]interface{}{
				"id":          f.SrNo,
				"file":        f.FilePath,
				"line":        f.LineNumber,
				"issue":       f.IssueName,
				"fix":         f.FixedCode,
				"remediation": f.Remediation,
			}
			json.NewEncoder(w).Encode(fix)
			return
		}
	}

	http.Error(w, `{"error":"finding not found"}`, http.StatusNotFound)
}

func getMemoryStats() map[string]uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]uint64{
		"alloc_mb":       m.Alloc / 1024 / 1024,
		"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
		"sys_mb":         m.Sys / 1024 / 1024,
		"num_gc":         uint64(m.NumGC),
	}
}

// sortMapTopN returns the top N entries from a map, sorted by value descending
func sortMapTopN(m map[string]int, n int) []map[string]interface{} {
	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	result := make([]map[string]interface{}, len(sorted))
	for i, item := range sorted {
		result[i] = map[string]interface{}{"label": item.Key, "count": item.Value}
	}
	return result
}

// openBrowser attempts to open the default web browser to the given URL
func openBrowser(url string) {
	// Give the server a small moment to actually start listening
	time.Sleep(500 * time.Millisecond)

	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		utils.LogInfo(fmt.Sprintf("Failed to auto-open browser: %v. Please visit %s manually.", err, url))
	}
}

func init() {
	startTime = time.Now()
}

// generateChartDashboardHTML creates the Chart.js dashboard section to inject into the HTML report
func generateChartDashboardHTML(findings []reporter.Finding) string {
	// Calculate data
	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	cweCounts := make(map[string]int)
	sourceCounts := make(map[string]int)

	for _, f := range findings {
		sevCounts[f.Severity]++
		if f.CWE != "" {
			cweCounts[f.CWE]++
		}
		if f.Source != "" {
			sourceCounts[f.Source]++
		}
	}

	// Top 8 CWEs
	topCWEs := sortMapTopN(cweCounts, 8)
	cweLabels := "["
	cweCnts := "["
	for i, item := range topCWEs {
		if i > 0 {
			cweLabels += ","
			cweCnts += ","
		}
		cweLabels += fmt.Sprintf("'%s'", item["label"])
		cweCnts += fmt.Sprintf("%d", item["count"])
	}
	cweLabels += "]"
	cweCnts += "]"

	// Source distribution
	sourceLabels := "["
	sourceCnts := "["
	first := true
	for k, v := range sourceCounts {
		if !first {
			sourceLabels += ","
			sourceCnts += ","
		}
		sourceLabels += fmt.Sprintf("'%s'", k)
		sourceCnts += fmt.Sprintf("%d", v)
		first = false
	}
	sourceLabels += "]"
	sourceCnts += "]"

	return fmt.Sprintf(`
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
  .chart-dashboard {
    background: linear-gradient(135deg, #0f0f23 0%%, #1a1a3e 100%%);
    padding: 40px 30px;
    margin: 30px 0;
    border-radius: 16px;
    border: 1px solid rgba(255,255,255,0.1);
  }
  .chart-dashboard h2 {
    color: #e2e8f0;
    text-align: center;
    font-size: 1.6rem;
    margin-bottom: 30px;
    font-weight: 700;
  }
  .charts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
    gap: 24px;
  }
  .chart-card {
    background: rgba(255,255,255,0.05);
    border-radius: 12px;
    padding: 24px;
    border: 1px solid rgba(255,255,255,0.08);
    backdrop-filter: blur(10px);
  }
  .chart-card h3 {
    color: #93c5fd;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 16px;
    text-align: center;
  }
  .chart-card canvas {
    max-height: 280px;
  }
</style>

<div class="chart-dashboard">
  <h2>📊 Visual Analytics Dashboard</h2>
  <div class="charts-grid">
    <div class="chart-card">
      <h3>Severity Distribution</h3>
      <canvas id="severityChart"></canvas>
    </div>
    <div class="chart-card">
      <h3>Top CWE Categories</h3>
      <canvas id="cweChart"></canvas>
    </div>
    <div class="chart-card">
      <h3>Detection Sources</h3>
      <canvas id="sourceChart"></canvas>
    </div>
  </div>
</div>

<script>
  Chart.defaults.color = '#94a3b8';
  Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';

  // Severity Pie Chart
  new Chart(document.getElementById('severityChart'), {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
      datasets: [{
        data: [%d, %d, %d, %d, %d],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#6366f1'],
        borderWidth: 2,
        borderColor: '#0f0f23'
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { padding: 15, usePointStyle: true } }
      }
    }
  });

  // CWE Bar Chart
  new Chart(document.getElementById('cweChart'), {
    type: 'bar',
    data: {
      labels: %s,
      datasets: [{
        label: 'Findings',
        data: %s,
        backgroundColor: 'rgba(99, 102, 241, 0.7)',
        borderColor: '#818cf8',
        borderWidth: 1,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } }
      }
    }
  });

  // Source Doughnut Chart
  new Chart(document.getElementById('sourceChart'), {
    type: 'doughnut',
    data: {
      labels: %s,
      datasets: [{
        data: %s,
        backgroundColor: ['#06b6d4', '#8b5cf6', '#f43f5e', '#10b981', '#f59e0b', '#3b82f6'],
        borderWidth: 2,
        borderColor: '#0f0f23'
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { padding: 15, usePointStyle: true } }
      }
    }
  });
</script>
`,
		sevCounts["critical"], sevCounts["high"], sevCounts["medium"], sevCounts["low"], sevCounts["info"],
		cweLabels, cweCnts,
		sourceLabels, sourceCnts,
	)
}
