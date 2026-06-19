package output

import "github.com/agentscan/agentscan/pkg/models"

// mcpStatusZH returns a Chinese display label for the MCP auth status.
func mcpStatusZH(noAuth, authRequired bool) string {
	if authRequired {
		return "需认证"
	}
	if noAuth {
		return "无认证"
	}
	return "已认证"
}

// mcpStatusEN returns the English display label for the MCP auth status.
func mcpStatusEN(noAuth, authRequired bool) string {
	if authRequired {
		return "auth-required"
	}
	if noAuth {
		return "no-auth"
	}
	return "auth"
}

// a2aExposureStatusLabel returns a display label for an A2A exposure status.
// zh=true returns Chinese; zh=false returns the raw constant string (English).
func a2aExposureStatusLabel(status models.A2AExposureStatus, zh bool) string {
	if !zh {
		return string(status)
	}
	switch status {
	case models.A2AExposureJSONRPCNoAuth:
		return "无认证 JSON-RPC"
	case models.A2AExposureAuthRequired:
		return "需认证"
	case models.A2AExposureDisabled:
		return "端点已禁用"
	case models.A2AExposureCardPublic:
		return "公开 Agent Card"
	case models.A2AExposureProbable:
		return "疑似 A2A Agent"
	case models.A2AExposureNonA2ADiscovery:
		return "非 A2A 协议"
	default:
		return string(status)
	}
}

// a2aProfileLabel returns a display label for an A2A profile.
// zh=true returns Chinese; zh=false returns the raw constant string (English).
func a2aProfileLabel(profile models.A2AProfile, zh bool) string {
	if !zh {
		return string(profile)
	}
	switch profile {
	case models.A2AProfileAgentCard:
		return "官方 agent-card.json"
	case models.A2AProfileLegacyAgentJSON:
		return "兼容 agent.json"
	case models.A2AProfileProbable:
		return "疑似 A2A"
	default:
		return string(profile)
	}
}

// a2aDeclaredAuthLabel translates declared auth value.
func a2aDeclaredAuthLabel(declared string, zh bool) string {
	if !zh {
		return declared
	}
	switch declared {
	case "declared_none":
		return "未声明认证"
	case "declared_required":
		return "声明需认证"
	case "declared_ambiguous":
		return "认证声明不完整"
	default:
		return declared
	}
}
