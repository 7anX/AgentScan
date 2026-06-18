package output

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/agentscan/agentscan/pkg/models"
)

type htmlReport struct {
	Lang        reportLanguage
	GeneratedAt string
	Summary     JSONSummary
	Servers     []htmlServer
}

type reportLanguage struct {
	Code                 string
	Title                string
	Subtitle             string
	Generated            string
	Summary              string
	TotalServers         string
	NoAuth               string
	AuthRequired         string
	Honeypots            string
	Exposure             string
	Results              string
	Target               string
	Transport            string
	Protocol             string
	Status               string
	Server               string
	Tools                string
	Resources            string
	Templates            string
	Prompts              string
	Score                string
	Details              string
	NoResults            string
	UnavailableAuth      string
	HoneypotSignals      string
	ToolList             string
	ResourceList         string
	ResourceTemplateList string
	PromptList           string
	None                 string
}

type htmlServer struct {
	Target            string
	URL               string
	Endpoint          string
	Transport         string
	ProtocolVersion   string
	Status            string
	StatusClass       string
	ServerInfo        string
	FingerprintScore  string
	ToolCount         int
	ResourceCount     int
	TemplateCount     int
	PromptCount       int
	HoneypotSuspected bool
	HoneypotScore     int
	HoneypotSignals   string
	AuthRequired      bool
	Tools             []models.MCPTool
	Resources         []models.MCPResource
	ResourceTemplates []models.MCPResourceTemplate
	Prompts           []models.MCPPrompt
}

func WriteHTMLReports(results []*models.MCPServer, baseDir string) (string, error) {
	reportDir, err := createReportDir(baseDir)
	if err != nil {
		return "", err
	}

	reports := []struct {
		name string
		lang reportLanguage
	}{
		{name: "report_zh.html", lang: zhReportLanguage()},
		{name: "report_en.html", lang: enReportLanguage()},
	}

	for _, r := range reports {
		path := filepath.Join(reportDir, r.name)
		if err := writeHTMLReport(path, results, r.lang); err != nil {
			return "", err
		}
	}
	if err := writeTextReports(reportDir, results); err != nil {
		return "", err
	}

	return reportDir, nil
}

func createReportDir(baseDir string) (string, error) {
	if baseDir == "" {
		baseDir = "."
	}

	name := "agentscan-report-" + time.Now().Format("20060102-150405")
	path := filepath.Join(baseDir, name)
	for i := 1; ; i++ {
		err := os.Mkdir(path, 0755)
		if err == nil {
			return path, nil
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("create HTML report directory: %w", err)
		}
		path = filepath.Join(baseDir, fmt.Sprintf("%s-%02d", name, i))
	}
}

func writeHTMLReport(path string, results []*models.MCPServer, lang reportLanguage) error {
	data := htmlReport{
		Lang:        lang,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Summary:     summarizeResults(results),
		Servers:     buildHTMLServers(results),
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create HTML report: %w", err)
	}
	defer f.Close()

	if err := htmlTemplate.Execute(f, data); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	return nil
}

func summarizeResults(results []*models.MCPServer) JSONSummary {
	summary := JSONSummary{Total: len(results)}
	for _, r := range results {
		if r.NoAuth {
			summary.Unauthenticated++
		}
		if r.AuthRequired {
			summary.AuthRequired++
		}
		if r.Honeypot.Suspected {
			summary.Honeypots++
		}
		summary.TotalTools += r.ToolCount
		summary.TotalResources += r.ResourceCount
		summary.TotalResourceTemplates += r.ResourceTemplateCount
		summary.TotalPrompts += r.PromptCount
	}
	return summary
}

func buildHTMLServers(results []*models.MCPServer) []htmlServer {
	servers := make([]htmlServer, 0, len(results))
	for _, r := range results {
		protocol := r.ProtocolVersion
		if protocol == "" {
			protocol = "unknown"
		}

		status := "auth"
		statusClass := "status-neutral"
		if r.AuthRequired {
			status = "auth-required"
			statusClass = "status-warning"
		} else if r.NoAuth {
			status = "no-auth"
			statusClass = "status-danger"
		}

		servers = append(servers, htmlServer{
			Target:            fmt.Sprintf("%s:%d%s", r.IP, r.Port, r.Endpoint),
			URL:               r.URL,
			Endpoint:          r.Endpoint,
			Transport:         htmlTransportLabel(r.Transport),
			ProtocolVersion:   protocol,
			Status:            status,
			StatusClass:       statusClass,
			ServerInfo:        htmlServerLabel(r),
			FingerprintScore:  fmt.Sprintf("%.2f", r.FingerprintScore),
			ToolCount:         r.ToolCount,
			ResourceCount:     r.ResourceCount,
			TemplateCount:     r.ResourceTemplateCount,
			PromptCount:       r.PromptCount,
			HoneypotSuspected: r.Honeypot.Suspected,
			HoneypotScore:     r.Honeypot.Score,
			HoneypotSignals:   strings.Join(r.Honeypot.Signals, ", "),
			AuthRequired:      r.AuthRequired,
			Tools:             sortedTools(r.Tools),
			Resources:         sortedResources(r.Resources),
			ResourceTemplates: sortedResourceTemplates(r.ResourceTemplates),
			Prompts:           sortedPrompts(r.Prompts),
		})
	}
	return servers
}

func sortedTools(items []models.MCPTool) []models.MCPTool {
	out := append([]models.MCPTool(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func sortedResources(items []models.MCPResource) []models.MCPResource {
	out := append([]models.MCPResource(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].URI) < strings.ToLower(out[j].URI)
	})
	return out
}

func sortedResourceTemplates(items []models.MCPResourceTemplate) []models.MCPResourceTemplate {
	out := append([]models.MCPResourceTemplate(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].URITemplate) < strings.ToLower(out[j].URITemplate)
	})
	return out
}

func sortedPrompts(items []models.MCPPrompt) []models.MCPPrompt {
	out := append([]models.MCPPrompt(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func writeTextReports(reportDir string, results []*models.MCPServer) error {
	files := map[string]string{
		"summary.txt":       buildSummaryText(results),
		"all_findings.txt":  buildFindingsText(results, func(*models.MCPServer) bool { return true }),
		"exposed.txt":       buildFindingsText(results, func(s *models.MCPServer) bool { return s.NoAuth && !s.AuthRequired }),
		"auth_required.txt": buildFindingsText(results, func(s *models.MCPServer) bool { return s.AuthRequired }),
		"tools.txt":         buildToolsText(results),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(reportDir, name), []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func buildSummaryText(results []*models.MCPServer) string {
	summary := summarizeResults(results)
	var b strings.Builder
	fmt.Fprintf(&b, "AgentScan summary\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "Total servers: %d\n", summary.Total)
	fmt.Fprintf(&b, "No auth: %d\n", summary.Unauthenticated)
	fmt.Fprintf(&b, "Auth required: %d\n", summary.AuthRequired)
	fmt.Fprintf(&b, "Suspected honeypots: %d\n", summary.Honeypots)
	fmt.Fprintf(&b, "Tools: %d\n", summary.TotalTools)
	fmt.Fprintf(&b, "Resources: %d\n", summary.TotalResources)
	fmt.Fprintf(&b, "Resource templates: %d\n", summary.TotalResourceTemplates)
	fmt.Fprintf(&b, "Prompts: %d\n", summary.TotalPrompts)
	return b.String()
}

func buildFindingsText(results []*models.MCPServer, include func(*models.MCPServer) bool) string {
	var b strings.Builder
	for _, s := range results {
		if !include(s) {
			continue
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\ttools=%d\tresources=%d\ttemplates=%d\tprompts=%d\t%s\n",
			statusLabel(s),
			reportURL(s),
			htmlTransportLabel(s.Transport),
			emptyAsUnknown(s.ProtocolVersion),
			s.ToolCount,
			s.ResourceCount,
			s.ResourceTemplateCount,
			s.PromptCount,
			oneLine(htmlServerLabel(s)),
		)
	}
	return b.String()
}

func buildToolsText(results []*models.MCPServer) string {
	var b strings.Builder
	for _, s := range results {
		for _, tool := range sortedTools(s.Tools) {
			fmt.Fprintf(&b, "%s\t%s\t%s\n", reportURL(s), oneLine(tool.Name), oneLine(tool.Description))
		}
	}
	return b.String()
}

func reportURL(s *models.MCPServer) string {
	return s.URL + s.Endpoint
}

func statusLabel(s *models.MCPServer) string {
	if s.AuthRequired {
		return "auth-required"
	}
	if s.NoAuth {
		return "no-auth"
	}
	return "auth"
}

func emptyAsUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func oneLine(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	v = strings.ReplaceAll(v, "\t", " ")
	return strings.TrimSpace(v)
}

func htmlTransportLabel(t models.Transport) string {
	switch t {
	case models.TransportStreamableHTTP:
		return "streamable-http"
	case models.TransportHTTPSSELegacy:
		return "sse-legacy"
	default:
		if t == "" {
			return "unknown"
		}
		return string(t)
	}
}

func htmlServerLabel(s *models.MCPServer) string {
	switch {
	case s.ServerName != "" && s.ServerVersion != "" && s.ServerName != s.ServerVersion:
		return fmt.Sprintf("%s (%s)", s.ServerName, s.ServerVersion)
	case s.ServerName != "":
		return s.ServerName
	case s.ServerVersion != "":
		return s.ServerVersion
	default:
		return "-"
	}
}

func zhReportLanguage() reportLanguage {
	return reportLanguage{
		Code:                 "zh-CN",
		Title:                "AgentScan 扫描报告",
		Subtitle:             "AI Agent 协议暴露面扫描结果",
		Generated:            "生成时间",
		Summary:              "概览",
		TotalServers:         "发现服务",
		NoAuth:               "无需认证",
		AuthRequired:         "需要认证",
		Honeypots:            "疑似蜜罐",
		Exposure:             "暴露能力",
		Results:              "服务列表",
		Target:               "目标",
		Transport:            "传输",
		Protocol:             "协议版本",
		Status:               "状态",
		Server:               "服务信息",
		Tools:                "工具",
		Resources:            "资源",
		Templates:            "资源模板",
		Prompts:              "提示词",
		Score:                "指纹分",
		Details:              "详情",
		NoResults:            "没有发现 MCP 服务。",
		UnavailableAuth:      "该服务需要认证，工具和资源详情不可用。",
		HoneypotSignals:      "蜜罐信号",
		ToolList:             "工具列表",
		ResourceList:         "资源列表",
		ResourceTemplateList: "资源模板",
		PromptList:           "提示词",
		None:                 "无",
	}
}

func enReportLanguage() reportLanguage {
	return reportLanguage{
		Code:                 "en",
		Title:                "AgentScan Report",
		Subtitle:             "AI agent protocol exposure scan results",
		Generated:            "Generated",
		Summary:              "Summary",
		TotalServers:         "Servers",
		NoAuth:               "No auth",
		AuthRequired:         "Auth required",
		Honeypots:            "Suspected honeypots",
		Exposure:             "Exposure",
		Results:              "Services",
		Target:               "Target",
		Transport:            "Transport",
		Protocol:             "Protocol",
		Status:               "Status",
		Server:               "Server",
		Tools:                "Tools",
		Resources:            "Resources",
		Templates:            "Templates",
		Prompts:              "Prompts",
		Score:                "Fingerprint",
		Details:              "Details",
		NoResults:            "No MCP services found.",
		UnavailableAuth:      "This service requires authentication. Tool and resource details are unavailable.",
		HoneypotSignals:      "Honeypot signals",
		ToolList:             "Tools",
		ResourceList:         "Resources",
		ResourceTemplateList: "Resource templates",
		PromptList:           "Prompts",
		None:                 "None",
	}
}

var htmlTemplate = template.Must(template.New("html-report").Parse(`<!doctype html>
<html lang="{{.Lang.Code}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Lang.Title}}</title>
  <style>
    :root {
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #5d6978;
      --line: #dbe1e8;
      --accent: #0f766e;
      --danger: #b42318;
      --warning: #b54708;
      --neutral: #344054;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.45;
    }
    header {
      background: #ffffff;
      border-bottom: 1px solid var(--line);
      padding: 28px 32px 22px;
    }
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px 20px 48px;
    }
    h1 { margin: 0 0 6px; font-size: 28px; }
    h2 { margin: 28px 0 12px; font-size: 18px; }
    h3 { margin: 18px 0 8px; font-size: 15px; }
    .subtitle, .muted { color: var(--muted); }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(5, minmax(130px, 1fr));
      gap: 12px;
    }
    .card, details {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .card { padding: 16px; }
    .metric { color: var(--muted); font-size: 13px; }
    .value { font-size: 28px; font-weight: 650; margin-top: 5px; }
    .table-wrap {
      overflow-x: auto;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    table { width: 100%; border-collapse: collapse; min-width: 860px; }
    th, td { padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { background: #f9fafb; color: var(--muted); font-size: 12px; font-weight: 650; text-transform: uppercase; }
    th button {
      appearance: none;
      border: 0;
      background: transparent;
      color: inherit;
      cursor: pointer;
      font: inherit;
      padding: 0;
      text-align: left;
      text-transform: inherit;
    }
    th button::after { content: "↕"; margin-left: 5px; color: #98a2b3; }
    th button.sorted-asc::after { content: "↑"; color: var(--accent); }
    th button.sorted-desc::after { content: "↓"; color: var(--accent); }
    tr:last-child td { border-bottom: 0; }
    code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      background: #eef2f6;
      padding: 2px 5px;
      border-radius: 4px;
      word-break: break-all;
    }
    .pill {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 650;
      background: #eef2f6;
      color: var(--neutral);
      white-space: nowrap;
    }
    .status-danger { background: #fee4e2; color: var(--danger); }
    .status-warning { background: #fef0c7; color: var(--warning); }
    .status-neutral { background: #e4e7ec; color: var(--neutral); }
    details { margin-top: 12px; padding: 0; }
    summary { cursor: pointer; padding: 13px 16px; font-weight: 650; }
    .detail-body { padding: 0 16px 16px; }
    .detail-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }
    .kv { border: 1px solid var(--line); border-radius: 6px; padding: 10px; background: #fbfcfd; }
    .kv span { display: block; color: var(--muted); font-size: 12px; }
    ul { padding-left: 20px; margin: 8px 0 0; }
    li { margin: 5px 0; }
    .description { color: var(--muted); margin-left: 4px; }
    .empty {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      color: var(--muted);
    }
    @media (max-width: 800px) {
      header { padding: 22px 20px 18px; }
      .summary-grid { grid-template-columns: repeat(2, minmax(130px, 1fr)); }
      .detail-grid { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
    }
  </style>
</head>
<body>
  <header>
    <h1>{{.Lang.Title}}</h1>
    <div class="subtitle">{{.Lang.Subtitle}}</div>
    <div class="muted">{{.Lang.Generated}}: {{.GeneratedAt}}</div>
  </header>
  <main>
    <section>
      <h2>{{.Lang.Summary}}</h2>
      <div class="summary-grid">
        <div class="card"><div class="metric">{{.Lang.TotalServers}}</div><div class="value">{{.Summary.Total}}</div></div>
        <div class="card"><div class="metric">{{.Lang.NoAuth}}</div><div class="value">{{.Summary.Unauthenticated}}</div></div>
        <div class="card"><div class="metric">{{.Lang.AuthRequired}}</div><div class="value">{{.Summary.AuthRequired}}</div></div>
        <div class="card"><div class="metric">{{.Lang.Honeypots}}</div><div class="value">{{.Summary.Honeypots}}</div></div>
        <div class="card"><div class="metric">{{.Lang.Exposure}}</div><div class="value">{{.Summary.TotalTools}}</div><div class="muted">{{.Lang.Tools}}</div></div>
      </div>
    </section>

    <section>
      <h2>{{.Lang.Results}}</h2>
      {{if .Servers}}
      <div class="table-wrap">
        <table id="findings-table">
          <thead>
            <tr>
              <th><button type="button" data-sort="target" data-type="text">{{.Lang.Target}}</button></th>
              <th><button type="button" data-sort="transport" data-type="text">{{.Lang.Transport}}</button></th>
              <th><button type="button" data-sort="protocol" data-type="text">{{.Lang.Protocol}}</button></th>
              <th><button type="button" data-sort="status" data-type="text">{{.Lang.Status}}</button></th>
              <th><button type="button" data-sort="server" data-type="text">{{.Lang.Server}}</button></th>
              <th><button type="button" data-sort="tools" data-type="number">{{.Lang.Tools}}</button></th>
              <th><button type="button" data-sort="resources" data-type="number">{{.Lang.Resources}}</button></th>
              <th><button type="button" data-sort="score" data-type="number">{{.Lang.Score}}</button></th>
            </tr>
          </thead>
          <tbody>
            {{range .Servers}}
            <tr data-target="{{.Target}}" data-transport="{{.Transport}}" data-protocol="{{.ProtocolVersion}}" data-status="{{.Status}}" data-server="{{.ServerInfo}}" data-tools="{{.ToolCount}}" data-resources="{{.ResourceCount}}" data-score="{{.FingerprintScore}}">
              <td><code>{{.Target}}</code></td>
              <td>{{.Transport}}</td>
              <td>{{.ProtocolVersion}}</td>
              <td><span class="pill {{.StatusClass}}">{{.Status}}</span></td>
              <td>{{.ServerInfo}}</td>
              <td>{{.ToolCount}}</td>
              <td>{{.ResourceCount}} / {{.TemplateCount}}</td>
              <td>{{.FingerprintScore}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>

      {{range .Servers}}
      <details>
        <summary>{{$.Lang.Details}}: {{.Target}}</summary>
        <div class="detail-body">
          <div class="detail-grid">
            <div class="kv"><span>{{$.Lang.Transport}}</span>{{.Transport}}</div>
            <div class="kv"><span>{{$.Lang.Status}}</span>{{.Status}}</div>
            <div class="kv"><span>{{$.Lang.Protocol}}</span>{{.ProtocolVersion}}</div>
            <div class="kv"><span>{{$.Lang.Score}}</span>{{.FingerprintScore}}</div>
          </div>
          {{if .AuthRequired}}
            <p class="muted">{{$.Lang.UnavailableAuth}}</p>
          {{end}}
          {{if .HoneypotSuspected}}
            <p><strong>{{$.Lang.HoneypotSignals}}:</strong> {{.HoneypotSignals}}</p>
          {{end}}

          <h3>{{$.Lang.ToolList}}</h3>
          {{if .Tools}}
          <ul>
            {{range .Tools}}<li><strong>{{.Name}}</strong>{{if .Description}} <span class="description">{{.Description}}</span>{{end}}</li>{{end}}
          </ul>
          {{else}}<p class="muted">{{$.Lang.None}}</p>{{end}}

          <h3>{{$.Lang.ResourceList}}</h3>
          {{if .Resources}}
          <ul>
            {{range .Resources}}<li><strong>{{.URI}}</strong>{{if .Name}} <span class="description">{{.Name}}</span>{{end}}</li>{{end}}
          </ul>
          {{else}}<p class="muted">{{$.Lang.None}}</p>{{end}}

          <h3>{{$.Lang.ResourceTemplateList}}</h3>
          {{if .ResourceTemplates}}
          <ul>
            {{range .ResourceTemplates}}<li><strong>{{.URITemplate}}</strong>{{if .Name}} <span class="description">{{.Name}}</span>{{end}}</li>{{end}}
          </ul>
          {{else}}<p class="muted">{{$.Lang.None}}</p>{{end}}

          <h3>{{$.Lang.PromptList}}</h3>
          {{if .Prompts}}
          <ul>
            {{range .Prompts}}<li><strong>{{.Name}}</strong>{{if .Description}} <span class="description">{{.Description}}</span>{{end}}</li>{{end}}
          </ul>
          {{else}}<p class="muted">{{$.Lang.None}}</p>{{end}}
        </div>
      </details>
      {{end}}
      {{else}}
      <div class="empty">{{.Lang.NoResults}}</div>
      {{end}}
    </section>
  </main>
  <script>
    (() => {
      const table = document.getElementById("findings-table");
      if (!table) return;
      const tbody = table.querySelector("tbody");
      let activeKey = "";
      let activeDir = "desc";
      table.querySelectorAll("button[data-sort]").forEach((button) => {
        button.addEventListener("click", () => {
          const key = button.dataset.sort;
          const type = button.dataset.type;
          activeDir = activeKey === key && activeDir === "desc" ? "asc" : "desc";
          activeKey = key;
          const rows = Array.from(tbody.querySelectorAll("tr"));
          rows.sort((a, b) => {
            const av = a.dataset[key] || "";
            const bv = b.dataset[key] || "";
            let cmp;
            if (type === "number") {
              cmp = (Number(av) || 0) - (Number(bv) || 0);
            } else {
              cmp = av.localeCompare(bv, undefined, { numeric: true, sensitivity: "base" });
            }
            return activeDir === "asc" ? cmp : -cmp;
          });
          rows.forEach((row) => tbody.appendChild(row));
          table.querySelectorAll("button[data-sort]").forEach((b) => b.classList.remove("sorted-asc", "sorted-desc"));
          button.classList.add(activeDir === "asc" ? "sorted-asc" : "sorted-desc");
        });
      });
    })();
  </script>
</body>
</html>
`))
