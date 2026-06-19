package output

// WriteUnifiedHTMLReports writes a single report containing both MCP and A2A results.
// Used by agentscan scan command. The report is written to the same directory as the
// MCP-only reports. Returns (reportDir, error).

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentscan/agentscan/pkg/models"
)

type unifiedReport struct {
	Lang        reportLanguage
	GeneratedAt string
	MCPSummary  JSONSummary
	A2ASummary  A2AJSONSummary
	MCPServers  []htmlServer
	A2AServers  []unifiedA2AServer
}

type unifiedA2AServer struct {
	Target          string
	AgentName       string
	CardURL         string
	Profile         string
	ExposureStatus  string
	StatusClass     string
	FingerprintScore string
	SkillCount      int
	Skills          []models.A2ASkill
	Interfaces      []models.A2AInterface
	ExposureSignals string
	DeclaredAuth    string
	AuthReasons     []string
	HasSkills       bool
}

// WriteUnifiedHTMLReports creates one report dir with report_zh.html and report_en.html,
// each containing MCP and A2A results in a tabbed layout.
func WriteUnifiedHTMLReports(
	mcpResults []*models.MCPServer,
	a2aResults []*models.A2AServer,
	baseDir string,
	targets []string,
	filePath string,
) (string, error) {
	reportDir, err := createReportDir(baseDir, targets, filePath)
	if err != nil {
		return "", err
	}

	reports := []struct {
		name string
		lang reportLanguage
	}{
		{name: "report.html", lang: zhReportLanguage()},
		{name: "report_en.html", lang: enReportLanguage()},
	}

	for _, r := range reports {
		path := filepath.Join(reportDir, r.name)
		if err := writeUnifiedReport(path, mcpResults, a2aResults, r.lang); err != nil {
			return "", err
		}
	}

	// summary.txt: combined MCP + A2A summary in one file
	summary := buildUnifiedSummaryText(mcpResults, a2aResults)
	if err := os.WriteFile(filepath.Join(reportDir, "summary.txt"), []byte(summary), 0644); err != nil {
		return "", fmt.Errorf("write summary.txt: %w", err)
	}
	// MCP text reports (prefixed)
	if err := writeTextReports(reportDir, mcpResults); err != nil {
		return "", err
	}
	// A2A text reports (prefixed)
	if err := writeA2ATextReports(reportDir, a2aResults); err != nil {
		return "", err
	}

	return reportDir, nil
}

func writeUnifiedReport(path string, mcpResults []*models.MCPServer, a2aResults []*models.A2AServer, lang reportLanguage) error {
	zh := lang.Code == "zh-CN"
	data := unifiedReport{
		Lang:        lang,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		MCPSummary:  summarizeResults(mcpResults),
		A2ASummary:  summarizeA2AResults(a2aResults),
		MCPServers:  buildHTMLServersLang(mcpResults, zh),
		A2AServers:  buildUnifiedA2AServersLang(a2aResults, zh),
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create unified HTML report: %w", err)
	}
	defer f.Close()

	if err := unifiedTemplate.Execute(f, data); err != nil {
		return fmt.Errorf("render unified HTML report: %w", err)
	}
	return nil
}

// writeA2ASection writes a standalone A2A report (used by agentscan a2a command).
// It wraps the A2A section in a full HTML document using the same light theme.
func writeA2ASection(w io.Writer, results []*models.A2AServer, lang reportLanguage, standalone bool) error {
	zh := lang.Code == "zh-CN"
	servers := buildUnifiedA2AServersLang(results, zh)
	if standalone {
		data := unifiedReport{
			Lang:        lang,
			GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
			A2ASummary:  summarizeA2AResults(results),
			A2AServers:  servers,
		}
		return standaloneA2ATemplate.Execute(w, data)
	}
	return nil
}

func buildUnifiedA2AServers(results []*models.A2AServer) []unifiedA2AServer {
	return buildUnifiedA2AServersLang(results, false)
}

func buildUnifiedA2AServersLang(results []*models.A2AServer, zh bool) []unifiedA2AServer {
	servers := make([]unifiedA2AServer, 0, len(results))
	for _, r := range results {
		statusClass := "pill status-neutral"
		switch r.ExposureStatus {
		case models.A2AExposureJSONRPCNoAuth:
			statusClass = "pill status-danger"
		case models.A2AExposureAuthRequired, models.A2AExposureDisabled:
			statusClass = "pill status-warning"
		}
		servers = append(servers, unifiedA2AServer{
			Target:           fmt.Sprintf("%s:%d%s", r.IP, r.Port, r.CardPath),
			AgentName:        r.AgentName,
			CardURL:          r.CardURL,
			Profile:          a2aProfileLabel(r.Profile, zh),
			ExposureStatus:   a2aExposureStatusLabel(r.ExposureStatus, zh),
			StatusClass:      statusClass,
			FingerprintScore: fmt.Sprintf("%.2f", r.FingerprintScore),
			SkillCount:       r.SkillCount,
			Skills:           r.Skills,
			Interfaces:       r.Interfaces,
			ExposureSignals:  strings.Join(r.ExposureSignals, ", "),
			DeclaredAuth:     a2aDeclaredAuthLabel(r.Evidence.Auth.Declared, zh),
			AuthReasons:      r.Evidence.Auth.Reasons,
			HasSkills:        len(r.Skills) > 0,
		})
	}
	return servers
}

// a2aIfaceStatusClass returns the pill CSS class for an A2A interface status.
func a2aIfaceStatusClass(status models.A2AInterfaceStatus) string {
	switch status {
	case models.A2AStatusNoAuthJSONRPCReachable, models.A2AStatusNoAuthStructuredRPCError:
		return "pill status-danger"
	case models.A2AStatusAuthRequired, models.A2AStatusExtendedCardAuthRequired:
		return "pill status-warning"
	default:
		return "pill status-neutral"
	}
}

// splitComma splits a comma-separated string into a slice for template use.
func splitCommaSlice(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ", ")
}

var tmplFuncs = template.FuncMap{
	"a2aIfaceStatusClass": a2aIfaceStatusClass,
	"splitComma":          splitCommaSlice,
}

// sharedCSS is the shared stylesheet used by all report variants.
const sharedCSS = `
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
    main { max-width: 1180px; margin: 0 auto; padding: 24px 20px 48px; }
    h1 { margin: 0 0 6px; font-size: 28px; }
    h2 { margin: 28px 0 12px; font-size: 18px; }
    h3 { margin: 18px 0 8px; font-size: 15px; }
    .subtitle, .muted { color: var(--muted); }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 8px;
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
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    th, td { padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { background: #f9fafb; color: var(--muted); font-size: 12px; font-weight: 650; text-transform: uppercase; }
    th button {
      appearance: none; border: 0; background: transparent; color: inherit;
      cursor: pointer; font: inherit; padding: 0; text-align: left; text-transform: inherit;
    }
    th button::after { content: "↕"; margin-left: 5px; color: #98a2b3; }
    th button.sorted-asc::after { content: "↑"; color: var(--accent); }
    th button.sorted-desc::after { content: "↓"; color: var(--accent); }
    tr:last-child td { border-bottom: 0; }
    code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      background: #eef2f6; padding: 2px 5px; border-radius: 4px;
      word-break: break-word; overflow-wrap: anywhere;
    }
    .pill {
      display: inline-block; border-radius: 999px; padding: 2px 8px;
      font-size: 12px; font-weight: 650; background: #eef2f6;
      color: var(--neutral); white-space: nowrap;
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
      gap: 10px; margin-bottom: 14px;
    }
    .kv { border: 1px solid var(--line); border-radius: 6px; padding: 10px; background: #fbfcfd; }
    .kv span { display: block; color: var(--muted); font-size: 12px; }
    .kv, .kv code, .kv div { min-width: 0; max-width: 100%; overflow-wrap: anywhere; word-break: break-word; }
    .evidence-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
      gap: 10px; margin-bottom: 14px;
    }
    .evidence-grid .kv { overflow: hidden; }
    .evidence-grid .wide { grid-column: 1 / -1; }
    .reason-list { display: flex; flex-direction: column; gap: 4px; }
    ul { padding-left: 20px; margin: 8px 0 0; }
    li { margin: 5px 0; }
    .description { color: var(--muted); margin-left: 4px; }
    .empty { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; color: var(--muted); }
    .tag { display: inline-block; background: #eef2f6; border-radius: 4px; padding: 1px 6px; font-size: 12px; margin: 1px; }
    .expandable-row { cursor: pointer; }
    .expandable-row:hover { background: #f0f4f8; }
    .expandable-row.expanded { background: #f0f9f7; }
    .detail-row td { padding: 0; background: #fbfcfd; }
    .detail-row .detail-body { padding: 12px 16px 16px; }
    /* Tabs */
    .tabs { display: flex; gap: 0; border-bottom: 2px solid var(--line); margin-bottom: 24px; }
    .tab-btn {
      padding: 10px 22px; font-size: 14px; font-weight: 600; cursor: pointer;
      border: none; background: none; color: var(--muted);
      border-bottom: 3px solid transparent; margin-bottom: -2px;
    }
    .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .protocol-badge {
      display: inline-block; font-size: 11px; font-weight: 700;
      padding: 1px 6px; border-radius: 4px; margin-right: 6px; vertical-align: middle;
    }
    .badge-mcp { background: #d1fae5; color: #065f46; }
    .badge-a2a { background: #dbeafe; color: #1e40af; }
    @media (max-width: 800px) {
      header { padding: 22px 20px 18px; }
      .summary-grid { grid-template-columns: repeat(2, minmax(130px, 1fr)); }
      .detail-grid { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
      .evidence-grid { grid-template-columns: minmax(0, 1fr); }
      .evidence-grid .wide { grid-column: auto; }
    }
`

const tableSortJS = `
  (() => {
    // Row expand/collapse
    document.querySelectorAll(".expandable-row").forEach(row => {
      row.addEventListener("click", () => {
        const detail = row.nextElementSibling;
        if (!detail || !detail.classList.contains("detail-row")) return;
        const open = detail.style.display !== "none";
        detail.style.display = open ? "none" : "table-row";
        row.classList.toggle("expanded", !open);
      });
    });
    // Table sorting (moves detail-row together with its parent)
    document.querySelectorAll("table[id]").forEach(table => {
      const tbody = table.querySelector("tbody");
      if (!tbody) return;
      let activeKey = "", activeDir = "desc";
      table.querySelectorAll("button[data-sort]").forEach(button => {
        button.addEventListener("click", e => {
          e.stopPropagation();
          const key = button.dataset.sort, type = button.dataset.type;
          activeDir = activeKey === key && activeDir === "desc" ? "asc" : "desc";
          activeKey = key;
          // collect row pairs: [expandable-row, detail-row]
          const pairs = [];
          const rows = Array.from(tbody.querySelectorAll("tr.expandable-row"));
          rows.forEach(r => {
            const detail = r.nextElementSibling;
            pairs.push({ main: r, detail: detail && detail.classList.contains("detail-row") ? detail : null });
          });
          pairs.sort((a, b) => {
            const av = a.main.dataset[key] || "", bv = b.main.dataset[key] || "";
            let cmp = type === "number" ? (Number(av)||0)-(Number(bv)||0)
                      : av.localeCompare(bv, undefined, {numeric:true, sensitivity:"base"});
            return activeDir === "asc" ? cmp : -cmp;
          });
          pairs.forEach(p => { tbody.appendChild(p.main); if (p.detail) tbody.appendChild(p.detail); });
          table.querySelectorAll("button[data-sort]").forEach(b => b.classList.remove("sorted-asc","sorted-desc"));
          button.classList.add(activeDir === "asc" ? "sorted-asc" : "sorted-desc");
        });
      });
    });
    // Tab switching
    document.querySelectorAll(".tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const panel = btn.dataset.tab;
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(panel).classList.add("active");
      });
    });
  })();
`

// mcpSectionHTML is the MCP results section used inside both unified and standalone templates.
// Details are rendered as hidden rows directly below their parent row in the table,
// toggled by clicking the row — no need to scroll to the bottom.
const mcpSectionHTML = `
    {{if .MCPServers}}
    <div class="table-wrap">
      <table id="mcp-table">
        <thead>
          <tr>
            <th><button type="button" data-sort="target" data-type="text">{{.Lang.Target}}</button></th>
            <th><button type="button" data-sort="transport" data-type="text">{{.Lang.Transport}}</button></th>
            <th><button type="button" data-sort="protocol" data-type="text">{{.Lang.Protocol}}</button></th>
            <th><button type="button" data-sort="status" data-type="text">{{.Lang.Status}}</button></th>
            <th><button type="button" data-sort="server" data-type="text">{{.Lang.Server}}</button></th>
            <th><button type="button" data-sort="tools" data-type="number">{{.Lang.Tools}}</button></th>
            <th><button type="button" data-sort="score" data-type="number">{{.Lang.Score}}</button></th>
          </tr>
        </thead>
        <tbody>
          {{range .MCPServers}}
          <tr class="expandable-row" data-target="{{.Target}}" data-transport="{{.Transport}}" data-protocol="{{.ProtocolVersion}}" data-status="{{.Status}}" data-server="{{.ServerInfo}}" data-tools="{{.ToolCount}}" data-score="{{.FingerprintScore}}">
            <td><code>{{.Target}}</code></td>
            <td>{{.Transport}}</td>
            <td>{{.ProtocolVersion}}</td>
            <td><span class="{{.StatusClass}}">{{.Status}}</span></td>
            <td>{{.ServerInfo}}</td>
            <td>{{.ToolCount}}</td>
            <td>{{.FingerprintScore}}</td>
          </tr>
          <tr class="detail-row" style="display:none">
            <td colspan="7">
              <div class="detail-body">
                <div class="detail-grid">
                  <div class="kv"><span>{{$.Lang.Transport}}</span>{{.Transport}}</div>
                  <div class="kv"><span>{{$.Lang.Status}}</span>{{.Status}}</div>
                  <div class="kv"><span>{{$.Lang.Protocol}}</span>{{.ProtocolVersion}}</div>
                  <div class="kv"><span>{{$.Lang.Score}}</span>{{.FingerprintScore}}</div>
                </div>
                <h3>{{$.Lang.Evidence}}</h3>
                <div class="evidence-grid">
                  <div class="kv wide"><span>URL</span><code>{{.EvidenceURL}}</code></div>
                  <div class="kv"><span>{{$.Lang.JSONRPC}}</span>{{.JSONRPCSummary}}</div>
                  <div class="kv"><span>{{$.Lang.FingerprintSignals}}</span>{{if .FingerprintSignals}}{{.FingerprintSignals}}{{else}}-{{end}}</div>
                  <div class="kv wide"><span>{{$.Lang.AuthReasons}}</span>{{if .AuthReasons}}<div class="reason-list">{{range .AuthReasons}}<div>{{.}}</div>{{end}}</div>{{else}}-{{end}}</div>
                </div>
                {{if .ResponseHeaders}}<h3>{{$.Lang.ResponseHeaders}}</h3><ul>{{range .ResponseHeaders}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
                {{if .AuthRequired}}<p class="muted">{{$.Lang.UnavailableAuth}}</p>{{end}}
                {{if .HoneypotSuspected}}<p><strong>{{$.Lang.HoneypotSignals}}:</strong> {{.HoneypotSignals}}</p>{{end}}
                {{if .HasAnyDetails}}
                  {{if .Tools}}<h3>{{$.Lang.ToolList}}</h3><ul>{{range .Tools}}<li><strong>{{.Name}}</strong>{{if .Description}} <span class="description">{{.Description}}</span>{{end}}</li>{{end}}</ul>{{end}}
                  {{if .Resources}}<h3>{{$.Lang.ResourceList}}</h3><ul>{{range .Resources}}<li><strong>{{.URI}}</strong>{{if .Name}} <span class="description">{{.Name}}</span>{{end}}</li>{{end}}</ul>{{end}}
                  {{if .ResourceTemplates}}<h3>{{$.Lang.ResourceTemplateList}}</h3><ul>{{range .ResourceTemplates}}<li><strong>{{.URITemplate}}</strong>{{if .Name}} <span class="description">{{.Name}}</span>{{end}}</li>{{end}}</ul>{{end}}
                  {{if .Prompts}}<h3>{{$.Lang.PromptList}}</h3><ul>{{range .Prompts}}<li><strong>{{.Name}}</strong>{{if .Description}} <span class="description">{{.Description}}</span>{{end}}</li>{{end}}</ul>{{end}}
                {{else}}<p class="muted">{{$.Lang.NoExposedDetails}}</p>{{end}}
              </div>
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{else}}<div class="empty">{{.Lang.NoResults}}</div>{{end}}
`

// a2aSectionHTML is the A2A results section used inside both unified and standalone templates.
const a2aSectionHTML = `
    {{if .A2AServers}}
    <div class="table-wrap">
      <table id="a2a-table">
        <thead>
          <tr>
            <th><button type="button" data-sort="target" data-type="text">{{.Lang.Target}}</button></th>
            <th><button type="button" data-sort="profile" data-type="text">{{.Lang.Protocol}}</button></th>
            <th><button type="button" data-sort="status" data-type="text">{{.Lang.Status}}</button></th>
            <th><button type="button" data-sort="agent" data-type="text">{{.Lang.Server}}</button></th>
            <th><button type="button" data-sort="skills" data-type="number">{{.Lang.Tools}}</button></th>
            <th><button type="button" data-sort="score" data-type="number">{{.Lang.Score}}</button></th>
          </tr>
        </thead>
        <tbody>
          {{range .A2AServers}}
          <tr class="expandable-row" data-target="{{.Target}}" data-profile="{{.Profile}}" data-status="{{.ExposureStatus}}" data-agent="{{.AgentName}}" data-skills="{{.SkillCount}}" data-score="{{.FingerprintScore}}">
            <td><code>{{.Target}}</code></td>
            <td>{{.Profile}}</td>
            <td><span class="{{.StatusClass}}">{{.ExposureStatus}}</span></td>
            <td>{{.AgentName}}</td>
            <td>{{.SkillCount}}</td>
            <td>{{.FingerprintScore}}</td>
          </tr>
          <tr class="detail-row" style="display:none">
            <td colspan="6">
              <div class="detail-body">
                <div class="detail-grid">
                  <div class="kv"><span>{{$.Lang.Protocol}}</span>{{.Profile}}</div>
                  <div class="kv"><span>{{$.Lang.Status}}</span><span class="{{.StatusClass}}">{{.ExposureStatus}}</span></div>
                  <div class="kv"><span>{{$.Lang.Score}}</span>{{.FingerprintScore}}</div>
                  {{if .DeclaredAuth}}<div class="kv"><span>Declared Auth</span>{{.DeclaredAuth}}</div>{{end}}
                </div>
                <div class="evidence-grid">
                  <div class="kv wide"><span>Card URL</span><code>{{.CardURL}}</code></div>
                  {{if .ExposureSignals}}<div class="kv wide"><span>Exposure Signals</span><div>{{range (splitComma .ExposureSignals)}}<span class="tag">{{.}}</span>{{end}}</div></div>{{end}}
                  {{if .AuthReasons}}<div class="kv wide"><span>{{$.Lang.AuthReasons}}</span><div class="reason-list">{{range .AuthReasons}}<div>{{.}}</div>{{end}}</div></div>{{end}}
                </div>
                {{if .Interfaces}}
                <h3>Interfaces</h3>
                {{range .Interfaces}}
                <div style="font-size:13px;padding:6px 0;border-bottom:1px solid var(--line)">
                  <span class="{{a2aIfaceStatusClass .Status}}">{{.Status}}</span>
                  &nbsp;<code>{{.URL}}</code>&nbsp;<span class="muted">{{.Binding}}</span>
                  {{if .PrivateHostAdvertised}}<br><span class="muted">advertised: {{.AdvertisedURL}}</span>{{end}}
                </div>
                {{end}}
                {{end}}
                {{if .HasSkills}}
                <h3>Skills</h3>
                <ul>{{range .Skills}}<li><strong>{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}</strong>{{if .Description}} <span class="description">{{.Description}}</span>{{end}}</li>{{end}}</ul>
                {{end}}
              </div>
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{else}}<div class="empty">No A2A agents found.</div>{{end}}
`

var unifiedTemplate = template.Must(template.New("unified").Funcs(tmplFuncs).Parse(`<!doctype html>
<html lang="{{.Lang.Code}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Lang.Title}}</title>
  <style>` + sharedCSS + `</style>
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
      <div style="margin-bottom:6px;font-size:13px;font-weight:600;color:var(--muted)">
        <span class="protocol-badge badge-mcp">MCP</span>
      </div>
      <div class="summary-grid" style="margin-bottom:16px">
        <div class="card"><div class="metric">{{.Lang.TotalServers}}</div><div class="value">{{.MCPSummary.Total}}</div></div>
        <div class="card"><div class="metric">{{.Lang.NoAuth}}</div><div class="value">{{.MCPSummary.Unauthenticated}}</div></div>
        <div class="card"><div class="metric">{{.Lang.AuthRequired}}</div><div class="value">{{.MCPSummary.AuthRequired}}</div></div>
        <div class="card"><div class="metric">{{.Lang.Honeypots}}</div><div class="value">{{.MCPSummary.Honeypots}}</div></div>
        <div class="card"><div class="metric">{{.Lang.Tools}}</div><div class="value">{{.MCPSummary.TotalTools}}</div></div>
      </div>
      <div style="margin-bottom:6px;font-size:13px;font-weight:600;color:var(--muted)">
        <span class="protocol-badge badge-a2a">A2A</span>
      </div>
      <div class="summary-grid">
        <div class="card"><div class="metric">Agents</div><div class="value">{{.A2ASummary.Total}}</div></div>
        <div class="card"><div class="metric">No-Auth RPC</div><div class="value">{{.A2ASummary.NoAuthJSONRPC}}</div></div>
        <div class="card"><div class="metric">{{.Lang.AuthRequired}}</div><div class="value">{{.A2ASummary.AuthRequired}}</div></div>
        <div class="card"><div class="metric">Disabled</div><div class="value">{{.A2ASummary.EndpointDisabled}}</div></div>
        <div class="card"><div class="metric">Skills</div><div class="value">{{.A2ASummary.TotalSkills}}</div></div>
      </div>
    </section>

    <section>
      <div class="tabs">
        <button class="tab-btn active" data-tab="tab-mcp">
          <span class="protocol-badge badge-mcp">MCP</span> {{.Lang.Results}} ({{len .MCPServers}})
        </button>
        <button class="tab-btn" data-tab="tab-a2a">
          <span class="protocol-badge badge-a2a">A2A</span> Agents ({{len .A2AServers}})
        </button>
      </div>

      <div id="tab-mcp" class="tab-panel active">
` + mcpSectionHTML + `
      </div>

      <div id="tab-a2a" class="tab-panel">
` + a2aSectionHTML + `
      </div>
    </section>
  </main>
  <script>` + tableSortJS + `</script>
</body>
</html>`))

var standaloneA2ATemplate = template.Must(template.New("a2a-standalone").Funcs(tmplFuncs).Parse(`<!doctype html>
<html lang="{{.Lang.Code}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentScan A2A — {{.Lang.Title}}</title>
  <style>` + sharedCSS + `</style>
</head>
<body>
  <header>
    <h1><span class="protocol-badge badge-a2a" style="font-size:18px">A2A</span> {{.Lang.Title}}</h1>
    <div class="subtitle">{{.Lang.Subtitle}}</div>
    <div class="muted">{{.Lang.Generated}}: {{.GeneratedAt}}</div>
  </header>
  <main>
    <section>
      <h2>{{.Lang.Summary}}</h2>
      <div class="summary-grid">
        <div class="card"><div class="metric">Agents</div><div class="value">{{.A2ASummary.Total}}</div></div>
        <div class="card"><div class="metric">No-Auth RPC</div><div class="value">{{.A2ASummary.NoAuthJSONRPC}}</div></div>
        <div class="card"><div class="metric">{{.Lang.AuthRequired}}</div><div class="value">{{.A2ASummary.AuthRequired}}</div></div>
        <div class="card"><div class="metric">Disabled</div><div class="value">{{.A2ASummary.EndpointDisabled}}</div></div>
        <div class="card"><div class="metric">Private Host</div><div class="value">{{.A2ASummary.PrivateHostAdvertised}}</div></div>
        <div class="card"><div class="metric">Skills</div><div class="value">{{.A2ASummary.TotalSkills}}</div></div>
      </div>
    </section>
    <section>
      <h2>{{.Lang.Results}}</h2>
` + a2aSectionHTML + `
    </section>
  </main>
  <script>` + tableSortJS + `</script>
</body>
</html>`))

func buildUnifiedSummaryText(mcpResults []*models.MCPServer, a2aResults []*models.A2AServer) string {
	mcp := summarizeResults(mcpResults)
	a2a := summarizeA2AResults(a2aResults)
	var b strings.Builder
	fmt.Fprintf(&b, "AgentScan unified summary\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "[MCP]\n")
	fmt.Fprintf(&b, "Total:         %d\n", mcp.Total)
	fmt.Fprintf(&b, "No auth:       %d\n", mcp.Unauthenticated)
	fmt.Fprintf(&b, "Auth required: %d\n", mcp.AuthRequired)
	fmt.Fprintf(&b, "Honeypots:     %d\n", mcp.Honeypots)
	fmt.Fprintf(&b, "Tools:         %d\n", mcp.TotalTools)
	fmt.Fprintf(&b, "Resources:     %d\n", mcp.TotalResources)
	fmt.Fprintf(&b, "Prompts:       %d\n\n", mcp.TotalPrompts)
	fmt.Fprintf(&b, "[A2A]\n")
	fmt.Fprintf(&b, "Total:         %d\n", a2a.Total)
	fmt.Fprintf(&b, "No-auth RPC:   %d\n", a2a.NoAuthJSONRPC)
	fmt.Fprintf(&b, "Auth required: %d\n", a2a.AuthRequired)
	fmt.Fprintf(&b, "Disabled:      %d\n", a2a.EndpointDisabled)
	fmt.Fprintf(&b, "Private host:  %d\n", a2a.PrivateHostAdvertised)
	fmt.Fprintf(&b, "Skills:        %d\n", a2a.TotalSkills)
	return b.String()
}