package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agentscan/agentscan/pkg/models"
)

type A2AJSONReport struct {
	Version string              `json:"version"`
	Summary A2AJSONSummary      `json:"summary"`
	Results []*models.A2AServer `json:"results"`
}

type A2AJSONSummary struct {
	Total                    int `json:"total"`
	Confirmed                int `json:"confirmed"`
	PublicCards              int `json:"public_cards"`
	NoAuthJSONRPC            int `json:"no_auth_jsonrpc"`
	AuthRequired             int `json:"auth_required"`
	EndpointDisabled         int `json:"endpoint_disabled"`
	PrivateHostAdvertised    int `json:"private_host_advertised"`
	ProbableAgentDiscoveries int `json:"probable_agent_discoveries"`
	TotalSkills              int `json:"total_skills"`
}

func WriteA2AJSON(results []*models.A2AServer, path string) error {
	report := A2AJSONReport{
		Version: "1.0",
		Summary: summarizeA2AResults(results),
		Results: results,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func PrintA2AServer(s *models.A2AServer, noColor bool) {
	FprintA2AServer(os.Stdout, s, noColor)
}

func FprintA2AServer(w io.Writer, s *models.A2AServer, noColor bool) {
	bold, reset, statusColor := "", "", ""
	if !noColor {
		bold = colorBold
		reset = colorReset
		switch s.ExposureStatus {
		case models.A2AExposureJSONRPCNoAuth:
			statusColor = colorGreen + colorBold
		case models.A2AExposureAuthRequired, models.A2AExposureDisabled:
			statusColor = colorYellow + colorBold
		}
	}

	target := fmt.Sprintf("%s:%d%s", s.IP, s.Port, s.CardPath)
	fmt.Fprintf(w, "%s[A2A]%s %-30s %-29s %s%s%s\n",
		bold, reset,
		target,
		string(s.Profile),
		statusColor, s.ExposureStatus, reset,
	)

	if s.AgentName != "" {
		fmt.Fprintf(w, "      agent    %s\n", s.AgentName)
	}
	fmt.Fprintf(w, "      exposed  skills=%d  interfaces=%d  score=%.2f\n",
		s.SkillCount, len(s.Interfaces), s.FingerprintScore)
	if len(s.ExposureSignals) > 0 {
		fmt.Fprintf(w, "      signals  %s\n", strings.Join(s.ExposureSignals, ", "))
	}
	for _, iface := range s.Interfaces {
		status := iface.Status
		if status == "" {
			status = models.A2AStatusUnknown
		}
		fmt.Fprintf(w, "      iface    %-34s %-30s %s\n", status, iface.Binding, iface.URL)
		if iface.PrivateHostAdvertised && iface.AdvertisedURL != "" {
			fmt.Fprintf(w, "               advertised=%s\n", iface.AdvertisedURL)
		}
	}
	fmt.Fprintln(w)
}

func PrintA2ASummary(results []*models.A2AServer, noColor bool) {
	bold, reset := "", ""
	if !noColor {
		bold = colorBold
		reset = colorReset
	}
	summary := summarizeA2AResults(results)
	fmt.Printf("%sSummary%s  A2A=%d  confirmed=%d  public-cards=%d  no-auth-jsonrpc=%d\n",
		bold, reset, summary.Total, summary.Confirmed, summary.PublicCards, summary.NoAuthJSONRPC)
	fmt.Printf("         auth-required=%d  disabled=%d  private-host=%d  probable=%d  skills=%d\n",
		summary.AuthRequired, summary.EndpointDisabled, summary.PrivateHostAdvertised, summary.ProbableAgentDiscoveries, summary.TotalSkills)
}

func summarizeA2AResults(results []*models.A2AServer) A2AJSONSummary {
	summary := A2AJSONSummary{Total: len(results)}
	for _, r := range results {
		if r.A2AConfirmed {
			summary.Confirmed++
		}
		if r.ExposureStatus == models.A2AExposureProbable {
			summary.ProbableAgentDiscoveries++
		}
		if r.ExposureStatus == models.A2AExposureCardPublic || r.A2AConfirmed {
			summary.PublicCards++
		}
		if r.NoAuth || r.ExposureStatus == models.A2AExposureJSONRPCNoAuth {
			summary.NoAuthJSONRPC++
		}
		if r.AuthRequired || r.ExposureStatus == models.A2AExposureAuthRequired {
			summary.AuthRequired++
		}
		if r.EndpointDisabled || r.ExposureStatus == models.A2AExposureDisabled {
			summary.EndpointDisabled++
		}
		for _, iface := range r.Interfaces {
			if iface.PrivateHostAdvertised {
				summary.PrivateHostAdvertised++
				break
			}
		}
		summary.TotalSkills += r.SkillCount
	}
	return summary
}
