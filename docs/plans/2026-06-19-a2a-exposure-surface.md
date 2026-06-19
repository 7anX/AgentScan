# A2A Exposure Surface Research and Implementation Plan

Date: 2026-06-19

## Goal

Add A2A exposure-surface support to AgentScan without changing the existing MCP scanner behavior.

The first implementation should answer three questions safely:

1. Is this HTTP service exposing an A2A Agent Card?
2. Is the advertised A2A endpoint unauthenticated, auth-required, or ambiguous?
3. What public attack surface is disclosed by the Agent Card: skills, protocols, input/output modes, push notifications, extended cards, extensions, and security schemes?

The scanner must stay read-only by default. It must not call methods that create tasks, cancel tasks, register push-notification callbacks, upload files, or cause agent execution unless the user explicitly enables an active verification mode later.

## External References

- Official A2A repository: https://github.com/a2aproject/A2A
- Official A2A specification: https://a2a-protocol.org/latest/specification/
- A2A discovery requires an Agent Card and defines the well-known URI `/.well-known/agent-card.json`: https://a2a-protocol.org/latest/specification/#82-discovery-mechanisms
- A2A authentication and authorization are delegated to standard web security, with requirements advertised in `securitySchemes`: https://a2a-protocol.org/latest/specification/#73-client-authentication-process
- A2A registers `application/a2a+json`, `A2A-Version`, `A2A-Extensions`, and the `agent-card.json` well-known URI: https://a2a-protocol.org/latest/specification/#14-iana-considerations
- AIP paper, identity and delegation across MCP/A2A: https://arxiv.org/abs/2603.24775
- Agent protocol security/conformance paper: https://arxiv.org/abs/2603.23801
- Comparative threat-modeling paper covering MCP/A2A/Agora/ANP: https://arxiv.org/abs/2602.11327
- Agent interoperability survey covering MCP/ACP/A2A/ANP: https://arxiv.org/abs/2505.02279

Local reference projects already present in this workspace:

- `reference/repos/MCPScan`: TypeScript scanner patterns for tool poisoning, SSRF, RCE vectors, overprivilege, auth-missing.
- `reference/repos/invariant-mcp-scan`: config and trust-oriented MCP scanner; useful for allowlist and guard ideas.
- `reference/repos/cisco-mcp-scanner`: static and behavioral analyzer taxonomy; useful for A2A skill-description risk rules.
- `reference/repos/honeymcp`: honeypot and detector patterns; useful for future A2A honeypot detection.

## Key A2A Exposure Surfaces

### 1. Public Discovery Metadata

The Agent Card is intentionally discoverable. It can expose:

- Agent name, description, provider, documentation URL, icon URL, version.
- `supportedInterfaces`: protocol binding, version, URL, and possibly tenant routing.
- `capabilities`: streaming, push notifications, extended Agent Card support, extensions.
- `skills`: IDs, names, descriptions, tags, examples, input modes, output modes.
- `securitySchemes` and `security`: OAuth/OIDC/API key/mTLS declarations and scopes.
- `signatures`: JWS metadata, `kid`, optional `jku`, and signing posture.

Risk: even when invocation is authenticated, the public Agent Card can leak internal product names, tenant IDs, private endpoints, sensitive scopes, workflow examples, or dangerous skill names.

### 2. Auth Boundary Mismatch

A2A expects servers to authenticate every request according to declared requirements. Common failure modes to detect:

- Agent Card declares no `securitySchemes` and no `security`.
- Agent Card declares security, but the selected interface accepts JSON-RPC without auth.
- Public card says `extendedAgentCard: true`, but `GetExtendedAgentCard` or `/extendedAgentCard` is reachable without auth.
- HTTP returns `401/403` but still leaks detailed JSON-RPC errors, stack traces, or extended metadata.

### 3. Skill and Modality Risk

`skills` are the A2A equivalent of a capability catalog. Risk signals:

- Dangerous verbs: execute, shell, command, deploy, delete, refund, transfer, approve, impersonate, kube, cloud, IAM.
- Sensitive domains: CRM, payroll, HR, ticketing, database, Kubernetes, cloud credentials, finance, email.
- High-risk modes: `application/json` with broad schemas, file upload/download, image/PDF processing, text/html output, URL/file references.
- Prompt-injection surface in skill descriptions/examples: instructions to ignore policies, exfiltrate context, forward credentials, or chain to other agents.

### 4. Push Notification and SSRF Surface

A2A has push notification configuration methods. Creating those configs is active and should not be performed by default.

Default scanner behavior:

- Only record whether the card advertises `pushNotifications: true`.
- Do not call `CreateTaskPushNotificationConfig`.
- In future active mode, validate only against a user-owned callback and require explicit `--active-a2a` consent.

Risk: webhook creation can become SSRF, internal callback probing, token exfiltration, or persistent callback registration.

### 5. Extended Agent Card

The public card may advertise an authenticated extended card.

Default scanner behavior:

- Record `capabilities.extendedAgentCard`.
- If an unauthenticated GET/JSON-RPC request returns the extended card, report `extended_card_no_auth`.
- If it returns `401/403`, report `extended_card_auth_required`.

Risk: extended cards can leak non-public skills, internal workflows, model/provider routing, or tenant-specific configuration.

### 6. Version and Binding Confusion

A2A supports JSON-RPC, gRPC, and HTTP+JSON/REST bindings. Early implementations and docs also used legacy names.

Scanner must:

- Prefer `supportedInterfaces` URLs over guessed endpoints.
- Retain URL paths from user-supplied targets.
- Capture `A2A-Version` and `A2A-Extensions` headers.
- Distinguish A2A from ACP when both expose `/.well-known/agent.json`.

## Fingerprint Strategy

Use weighted evidence, similar to MCP scoring.

Strong signals:

- `/.well-known/agent-card.json` returns JSON with required Agent Card shape: `name`, `description`, `capabilities`, `skills`.
- `supportedInterfaces[].protocolBinding` includes `JSONRPC`, `GRPC`, or `HTTP+JSON`.
- Response content type is `application/a2a+json` or `application/json` with strong A2A card shape. Do not require `application/a2a+json`; JSON-RPC bindings commonly use `application/json`.
- `A2A-Version` response header is present.

Medium signals:

- `/.well-known/agent.json` returns A2A-like fields and not ACP-like fields.
- Card includes A2A-specific `pushNotifications`, `extendedAgentCard`, `securitySchemes`, `security`, `signatures`.
- Interface URL accepts JSON-RPC and returns A2A-style error codes or `MethodNotFoundError`.

Negative signals:

- ACP-specific shape such as `agentId`, REST `runs` semantics, or BeeAI ACP endpoints.
- Generic OpenAPI/plugin manifests without A2A fields.
- HTML landing pages or static docs with only words like "agent".

Suggested threshold:

- `>= 0.65`: confirmed A2A.
- `0.45-0.64`: probable A2A, include only when `--verbose` or `--include-probable` exists later.
- `< 0.45`: ignore.

## Safe Probe Flow

Stage A: HTTP filter reuse

- Reuse current port scan and HTTP filter.
- Add A2A candidate paths:
  - `/.well-known/agent-card.json`
  - `/.well-known/agent.json`
  - user-provided URL path if it ends in `.json` or contains `agent-card`

Stage B: Agent Card probe

- `GET` candidate card URLs.
- Accept only bounded JSON bodies, e.g. 1 MiB.
- Store relevant headers: `Content-Type`, `Server`, `WWW-Authenticate`, `A2A-Version`, `A2A-Extensions`, `Location`.
- Parse to `A2AAgentCard` with a permissive struct plus raw maps for future fields.

Stage C: Interface classification

- For each `supportedInterfaces` entry:
  - Normalize URL, reject `file://`, private redirects, path traversal, and cross-host surprises unless the original card explicitly points to that host.
  - Classify binding as JSON-RPC, HTTP+JSON, gRPC, or unknown.
  - Do not execute task methods by default.

Stage D: Auth classification

- If card has no `securitySchemes` and no `security`, mark `card_no_declared_auth`.
- If JSON-RPC interface exists, send a harmless invalid/unknown method request only:
  - method: `AgentScanProbe`
  - expect `MethodNotFoundError` or auth challenge.
  - This verifies service presence without creating tasks.
- If request returns A2A-shaped JSON-RPC error without auth, mark `interface_no_auth_probe`.
- If `401/403` with auth headers, mark `interface_auth_required`.

Stage E: Extended card check

- Only when `extendedAgentCard: true`.
- Try the official read operation in a no-auth way:
  - JSON-RPC `GetExtendedAgentCard` if JSON-RPC binding exists.
  - GET `/extendedAgentCard` only if card/docs/interface hints indicate it.
- Treat success without auth as a finding.
- Treat `401/403` as expected auth-required.

## Detection Logic

The detector should produce a structured finding for every confirmed A2A service. Each finding has independent `fingerprint`, `auth`, `interfaces`, and `exposure` sections so later output formats can show both "why this is A2A" and "what is exposed".

### Input Normalization

For each HTTP candidate from the existing pipeline, build an A2A probe context:

- `baseURL`: scheme, host, port from HTTP filter.
- `hostname`: original hostname for TLS SNI and JSON output.
- `urlPath`: user-supplied path, if any.
- `cardCandidates`: ordered list of candidate card paths.

Candidate card paths:

1. User URL path when it ends in `.json`, contains `agent-card`, or equals `/.well-known/agent.json`.
2. `/.well-known/agent-card.json`.
3. `/.well-known/agent.json`.

Redirect policy:

- Follow same-host redirects.
- Reject cross-host redirects by default and record `cross_host_card_redirect`.
- Reject non-HTTP(S) schemes.
- Limit body to 1 MiB.

### Step 1: Agent Card Fetch

Send:

```http
GET <candidate-card-url>
Accept: application/a2a+json, application/json
User-Agent: AgentScan/<version>
```

Classify the response:

- `200` with parseable JSON: continue to shape scoring.
- `401/403`: possible protected card, record `card_auth_required`, but do not confirm A2A unless headers/body provide A2A-specific evidence.
- `404/410`: path miss.
- Other `4xx/5xx`: record only in verbose evidence.
- HTML or non-JSON response: ignore unless A2A headers are present.

### Step 2: Card Shape Scoring

Use a score instead of a single required-field check because early implementations and compatibility layers vary.

Positive signals:

- `name` string: +0.10
- `description` string: +0.10
- `capabilities` object: +0.15
- `skills` array: +0.20
- `supportedInterfaces` array: +0.20
- `securitySchemes` object or `security` array/object: +0.10
- `protocolVersion` or interface `version`: +0.10
- `Content-Type` contains `application/a2a+json`: +0.10 as an A2A/HTTP+JSON hint, not a JSON-RPC requirement.
- `A2A-Version` header exists: +0.20
- Any capability key from `streaming`, `pushNotifications`, `extendedAgentCard`, `extensions`: +0.10
- Any interface binding from `JSONRPC`, `HTTP+JSON`, `GRPC`: +0.15

Negative signals:

- ACP-like `agentId` plus `runs`/REST run fields: reject unless stronger A2A signals exist.
- ChatGPT plugin fields like `schema_version`, `api`, `auth` without A2A fields: reject.
- OpenAPI document fields like `openapi`, `paths`, `components` without A2A fields: reject.
- JSON-RPC response shape with `jsonrpc`, `result`, `error` at card URL: not an Agent Card.

Confirmation:

- `score >= 0.65`: confirmed A2A.
- `0.45 <= score < 0.65`: probable A2A, returned only with `--include-probable`.
- `< 0.45`: ignore.

### Step 3: Interface Extraction

Extract endpoint candidates from the card:

- `supportedInterfaces[].url`.
- Legacy or implementation-specific `url` / `endpoint` fields, if present.
- If no interface URL exists but card is confirmed, try origin `/a2a` once as `inferred_interface_url` with low confidence.

For each endpoint:

- Resolve relative URLs against the card URL.
- Only actively connect to `http` and `https` URLs.
- Reject path traversal.
- Record whether endpoint host differs from card host.
- Preserve the original advertised URL in evidence.
- Do not directly connect to `localhost`, loopback, or private-IP advertised endpoints. If the path looks like `/a2a` or `/api/a2a`, rebase only the path onto the public card origin and record `private_host_advertised`.
- Classify binding:
  - JSON-RPC when `protocolBinding` is `JSONRPC`.
  - HTTP+JSON when `protocolBinding` is `HTTP+JSON`.
  - gRPC when `protocolBinding` is `GRPC`.
  - unknown-jsonrpc-candidate when no binding is declared but the URL path hints `/a2a`, `/rpc`, or `/jsonrpc`.
  - unknown otherwise.

First milestone should actively probe only JSON-RPC and unknown-jsonrpc-candidate endpoints. HTTP+JSON/REST and gRPC are recorded but not actively verified unless a later explicit active mode is added.

### Step 4: Auth Posture Detection

Auth posture is determined from declaration plus live read-only probes.

Declared auth:

- `declared_none`: no `securitySchemes` and no `security`.
- `declared_required`: security requirements or schemes exist.
- `declared_ambiguous`: schemes exist but no effective requirement can be derived.

Live interface probe for JSON-RPC and unknown-jsonrpc-candidate endpoints:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "AgentScanProbe",
  "params": {}
}
```

Request headers:

```http
Content-Type: application/json
Accept: application/json
A2A-Version: <interface protocolVersion, card protocolVersion, or 1.0>
```

Expected classifications:

- `401/403` or `WWW-Authenticate`: `auth_required`.
- `200` with JSON-RPC `error` and method-not-found style code/message: `no_auth_interface_reachable`.
- `200` with any A2A-shaped response: `no_auth_interface_reachable`.
- any `4xx/5xx` with JSON-RPC `error.code == -32601`: `no_auth_interface_reachable`.
- JSON-RPC body with message like `A2A endpoint is disabled`, `not configured`, `maintenance`, or `placeholder`: `disabled_or_placeholder`.
- `400` with other A2A/JSON-RPC structured error: `no_auth_interface_reachable_low_confidence`.
- timeout/network error: `unknown`.

Do not call:

- task/send, message/send, SendMessage, SendStreamingMessage.
- cancel/resubscribe methods.
- push notification config create/delete methods.
- file upload or artifact retrieval methods.

### Step 5: Extended Card Exposure

Only run this step when the card advertises `capabilities.extendedAgentCard == true`.

Checks:

- JSON-RPC read probe: `GetExtendedAgentCard`.
- Optional GET probe only when the card advertises or links an extended-card URL.

Classification:

- Extended card returned without auth: `extended_card_no_auth`.
- `401/403`: `extended_card_auth_required`.
- `404/method not found`: `extended_card_not_found`.
- Other structured response: `extended_card_unknown`.

If an extended card is returned, scan it with the same card parser and compare new skills/security/interface fields against the public card. Any newly exposed skill is marked `non_public_skill_exposed`.

### Step 6: Exposure Signal Extraction

Run deterministic extractors over public and extended cards.

Metadata exposure:

- private IPs, localhost, `.internal`, `.local`, cloud metadata hosts.
- tenant IDs, workspace IDs, org IDs, cluster names.
- emails, Slack/Teams channels, ticketing project keys.
- docs URLs that point to private domains.

Credential exposure:

- API key/token patterns.
- cloud access key patterns.
- bearer/basic auth fragments.
- PEM/private key markers.
- webhook signing secrets.

Skill exposure:

- dangerous operations: execute, shell, command, terminal, deploy, delete, write, refund, transfer, approve, impersonate.
- privileged systems: kubernetes, k8s, iam, admin, root, sudo, database, postgres, mysql, snowflake, salesforce, jira, github, aws, azure, gcp.
- broad data operations: export, dump, backup, query, search all, read file, browse internal.

Mode exposure:

- file upload/download modes.
- `text/html`, `application/json`, `application/octet-stream`.
- URL, path, or raw command parameters in examples or schemas.

Protocol exposure:

- push notifications advertised.
- streaming advertised.
- extensions advertised, especially required extensions.
- cross-host or private-host interface URL.

### Step 7: Finding Construction

Each finding should include:

- `protocol: "a2a"`.
- network identity: IP, port, hostname, URL, card URL, interface URLs.
- fingerprint score and signals.
- auth status and evidence.
- public card summary.
- skill list and counts.
- exposure signals grouped by category.
- exposure status and evidence.
- raw card only when `--verbose-raw` is enabled.

Recommended evidence object:

```json
{
  "card": {
    "url": "...",
    "status_code": 200,
    "content_type": "application/a2a+json",
    "headers": {
      "A2A-Version": "..."
    },
    "fingerprint": {
      "score": 0.85,
      "signals": ["skills", "capabilities", "supported_interfaces"]
    }
  },
  "auth": {
    "declared": "required",
    "live": "no_auth_interface_reachable",
    "reasons": ["JSON-RPC method-not-found returned without auth"]
  },
  "exposure": {
    "signals": ["push_notifications_advertised", "dangerous_skill_keywords"]
  }
}
```

## Exposure Status Classification

AgentScan should not assign vulnerability-style risk levels in the A2A MVP. Keep the output aligned with the current MCP scanner: protocol identification, exposure enumeration, auth posture, and reproducible evidence.

Use evidence-driven statuses instead of `CRITICAL/HIGH/MEDIUM/LOW`:

- `card_public_a2a`: an A2A-shaped card is publicly readable, but no callable interface has been verified.
- `confirmed_a2a_agent_card`: official `/.well-known/agent-card.json` has strong A2A card evidence.
- `confirmed_a2a_legacy_agent_json`: compatibility `/.well-known/agent.json` has strong A2A-like evidence.
- `confirmed_a2a_jsonrpc_no_auth`: a JSON-RPC interface accepted the unknown-method probe and returned JSON-RPC `-32601` or equivalent without auth.
- `confirmed_a2a_auth_required`: card is readable, but the selected interface returns `401/403` or a clear auth challenge.
- `disabled_or_placeholder`: card is readable, but the interface clearly says it is disabled, not configured, maintenance-only, or a placeholder.
- `probable_agent_discovery`: agent metadata exists, but A2A-specific evidence is incomplete.
- `non_a2a_agent_discovery`: alternate schema or manifest detected, such as OpenAPI, ai-plugin, Agent Protocol/ANP, AMP agent discovery, or generic action-card format.

Status layering:

- Card readability is not endpoint reachability. `card_public_a2a` only means the card can be fetched and parsed.
- Card confirmation is structural. `confirmed_a2a_agent_card` and `confirmed_a2a_legacy_agent_json` require strong card evidence such as `skills`, `capabilities`, `supportedInterfaces`, `protocolVersion`, `url`, or equivalent legacy fields above threshold.
- Interface confirmation is live protocol evidence. `confirmed_a2a_jsonrpc_no_auth` requires a selected JSON-RPC endpoint to return `-32601` or equivalent to the unknown-method probe without authentication.
- Auth-required and disabled states are interface states layered on top of a public/confirmed card, not replacements for card evidence.

Summary accounting:

- A2A confirmed totals include `confirmed_a2a_agent_card`, `confirmed_a2a_legacy_agent_json`, `confirmed_a2a_jsonrpc_no_auth`, `confirmed_a2a_auth_required`, and `disabled_or_placeholder`.
- A2A public-card totals include `card_public_a2a` and confirmed card statuses.
- `probable_agent_discovery` is shown separately and only included when requested, e.g. `--include-probable`.
- `non_a2a_agent_discovery` is an exclusion/transfer status. Keep evidence in verbose/debug output, but do not count it as an A2A finding or mix it into A2A summary totals.

Do not merge these into one risk score. Consumers can triage from the evidence fields:

- public card fields and path;
- auth declaration;
- live interface status;
- advertised/private/cross-host endpoints;
- skill names and descriptions;
- push notification and extended-card capability flags;
- JSON-RPC status/error details from read-only probes.

The `system-admin-agent` cluster found in Quake is operationally important, but AgentScan should report it as `confirmed_a2a_jsonrpc_no_auth` with dangerous skill names, not as a built-in risk severity.

## Quake Test Findings and Optimizations

Test input:

- File: `tartest/body=.well-knownagent.json AND country China.txt`
- Targets: 119 URLs
- Read-only card requests: 238
- Candidate paths: `/.well-known/agent-card.json`, `/.well-known/agent.json`
- Per-request timeout: 3 seconds
- Concurrency: 40

Observed result:

- Confirmed A2A/legacy A2A-like cards: 16
- Probable agent cards: 6
- Weak non-A2A agent discovery documents: 5
- Official `/.well-known/agent-card.json` confirmed hits: 0
- Legacy `/.well-known/agent.json` confirmed hits: 16

Confirmed card families:

- `OmniRoute AI Gateway`: 10 deployments
- `EasyClaw`: 4 deployments
- `MiCount Low-Code Advisor`: 1 deployment
- `AgentHub - A2A Agent Directory`: 1 deployment

### Optimization 1: Add Legacy A2A Profile

The real-world China sample is dominated by `/.well-known/agent.json`, not the official latest `agent-card.json`. Most confirmed cards lack `supportedInterfaces`, but include:

- `name`
- `description`
- `url`
- `version`
- `capabilities`
- `skills`
- `authentication`
- sometimes `protocol: "A2A"`
- sometimes `schemaVersion`
- sometimes `defaultInputModes` / `defaultOutputModes`
- sometimes `supportsAuthenticatedExtendedCard`

Scanner implication:

- Keep latest Agent Card scoring.
- Add `legacy_agent_json` profile.
- Confirm `legacy_agent_json` when `name + description + capabilities + skills` exist and `capabilities` has agent-like keys.
- Do not require `supportedInterfaces` for legacy cards.

Updated score additions:

- `protocol == "A2A"`: +0.25
- `schemaVersion` or `schema_version`: +0.05
- top-level `url`: +0.10
- `authentication`: +0.10
- `defaultInputModes` / `defaultOutputModes`: +0.10
- `supportsAuthenticatedExtendedCard`: +0.10

### Optimization 2: More Agent-Discovery Exclusions

The same path is used by other ecosystems. These should not be reported as A2A unless stronger A2A signals exist:

- `"$schema": "https://agentprotocol.ai/schema/agent.json"`: Agent Protocol / ANP-like card.
- `schema: "amp.agent-discovery.v2"`: AMP agent discovery.
- Cards with `capabilities.actions` but no `skills`: generic action directory, not A2A.
- `protocols` object without `skills`: probable generic agent profile.

Scanner implication:

- Add negative classifier `agent_protocol_like`.
- Add negative classifier `amp_agent_discovery_like`.
- Add negative classifier `generic_actions_card`.
- Keep these in verbose/probable output only if `--include-probable` is set.

### Optimization 3: Interface Endpoint Inference

Many legacy cards expose the callable URL in top-level `url`, not in `supportedInterfaces`.

Observed examples:

- `url: "http://localhost:20128/a2a"` in public cards.
- `url: "https://easyclaw.link/api/a2a/EasyClaw"`.
- directory cards where `url` is a website path, not a JSON-RPC endpoint.

Inference rules:

- If `url` path contains `/a2a`, treat it as an interface candidate.
- If `url` host is `localhost`, `127.0.0.1`, `0.0.0.0`, or private IP, rebase the path onto the public card origin and record `private_host_rebased`.
- If `url` path does not look like `/a2a` or `/api/a2a`, treat it as documentation/homepage unless the probe returns JSON-RPC.
- If no candidate exists, try origin `/a2a` once as low-confidence inference.

### Optimization 4: JSON-RPC Error Classification

The live unknown-method probe showed these patterns:

- HTTP `200` with JSON-RPC `-32601`: interface is reachable without auth.
- HTTP `404` with JSON-RPC `-32601`: interface is still reachable without auth; some implementations use HTTP 404 for method-not-found.
- HTTP `503` with JSON-RPC `-32000` and message like "A2A endpoint is disabled": endpoint exists but disabled; report as `a2a_endpoint_disabled`, not as high-risk no-auth invocation.
- HTTP `405` HTML or generic JSON: likely wrong endpoint or method not allowed; do not classify as live no-auth.

Scanner implication:

- Do not rely only on HTTP status.
- Parse JSON-RPC body for all `2xx`, `4xx`, and `5xx` responses.
- `jsonrpc == "2.0"` plus `error.code == -32601` is strong `no_auth_interface_reachable` evidence.
- Disabled endpoint messages should be a separate exposure status, not a no-auth interface finding.

### Optimization 5: Exposure Signal Tuning From Real Data

New practical exposure signals:

- `legacy_agent_json_public`
- `private_host_advertised`
- `private_host_rebased_endpoint_reachable`
- `jsonrpc_method_not_found_no_auth`
- `a2a_endpoint_disabled`
- `push_notifications_true`
- `cross_host_interface_url`
- `http_plaintext_card`

Status adjustments:

- Public card only, no live interface: `card_public_a2a`.
- Public card plus private/localhost callable URL: add `private_host_advertised`.
- Public card plus JSON-RPC method-not-found without auth: `confirmed_a2a_jsonrpc_no_auth`.
- Public card plus disabled A2A endpoint: `disabled_or_placeholder`.
- Public card plus push notifications and live no-auth interface: `confirmed_a2a_jsonrpc_no_auth` plus `push_notifications_true`.

### Optimization 6: Deduplication

The Quake sample contains many duplicate deployments of the same product. Output should support both raw findings and clustered findings.

Cluster keys:

- normalized card hash, if raw card retained internally.
- `name + version + skill IDs`.
- advertised endpoint path.
- provider/product name.

Recommended output:

- Raw JSON keeps every target.
- Terminal/HTML groups duplicate product families and shows affected endpoints below the group.

### Optimization 7: Quake Query Refinement

The query `body=.well-knownagent.json` catches a broad set of agent-discovery documents. Better high-precision queries:

```text
body="/.well-known/agent.json" && body="\"skills\"" && body="\"capabilities\""
body="\"protocol\":\"A2A\"" || body="\"protocol\": \"A2A\""
body="\"pushNotifications\"" && body="\"skills\""
body="\"/a2a\"" && body="\"skills\"" && body="\"capabilities\""
```

High-recall queries:

```text
body="/.well-known/agent.json"
body="\"agent.json\"" && body="\"capabilities\""
body="\"supportedInterfaces\"" || body="\"agent-card.json\""
```

False-positive filters:

```text
NOT body="agentprotocol.ai/schema/agent.json"
NOT body="amp.agent-discovery"
NOT body="openapi"
```

### Follow-up Query Validation

Follow-up input files:

- `tartest/body=.well-knownagent.json AND body=skills AND body=capabilities and China.txt`
- `tartest/body=.well-knownagent.json AND body=skills AND body=capabilities and USA.txt`

Results:

| Region | Targets | Card requests | Confirmed legacy A2A | Confirmed latest A2A | Probable | Negative |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| China | 6 | 12 | 3 | 0 | 0 | 0 |
| USA | 81 | 162 | 12 | 1 | 0 | 0 |

Confirmed products:

- China: `Routiform AI Gateway`, `OmniRoute AI Gateway`.
- USA: mostly `OmniRoute AI Gateway`, plus `Agentform`, `CodeReclaimers LLC Capability Oracle`.

Interface probe findings using only unknown JSON-RPC method `AgentScanProbe`:

| Region | Endpoint probes | JSON-RPC method-not-found without auth | A2A endpoint disabled | Network/redirect/unknown |
| --- | ---: | ---: | ---: | ---: |
| China | 3 | 2 | 1 | 0 |
| USA | 13 | 2 | 7 | 4 |

Key conclusions:

- `body=.well-knownagent.json AND body=skills AND body=capabilities` is a good high-precision query.
- `skills + capabilities` removed the earlier generic agent-discovery false positives in this sample.
- Most hits are still legacy `/.well-known/agent.json`, not latest `/.well-known/agent-card.json`.
- `agent-card.json` did appear once in the USA sample, so both paths must remain in the scanner.
- Many cards advertise `http://localhost:20128/a2a`; rebasing the `/a2a` path onto the public origin correctly found JSON-RPC responses.
- `404` plus JSON-RPC `-32601` is a real no-auth interface signal and must not be discarded as a normal HTTP 404.
- `503` plus JSON-RPC message `A2A endpoint is disabled` should be reported separately from exploitable no-auth interfaces.

Updated implementation recommendation:

- Default confirmed output should include both `confirmed_a2a_agent_card` and `confirmed_a2a_legacy_agent_json`.
- Terminal summary should split:
  - public card exposure
  - no-auth JSON-RPC endpoint reachable
  - A2A endpoint disabled
  - private/localhost endpoint advertised
- Add regression fixtures for:
  - legacy `agent.json` with `localhost:20128/a2a`.
  - latest `agent-card.json` with `supportsAuthenticatedExtendedCard`.
  - HTTP 404 JSON-RPC `-32601`.
  - HTTP 503 JSON-RPC `A2A endpoint is disabled`.

### Broad A2A Query Validation

Follow-up input file:

- `tartest/bodya2a AND bodyskills AND bodycapabilities AND country United States of America.txt`

This query is broader than the `.well-known/agent.json + skills + capabilities` query because it does not require the well-known path string. It is useful for finding more implementations, but it has lower conversion and more slow/non-HTTP targets.

Card probe results:

| Region | Targets | Card requests | HTTP 200 | Confirmed legacy A2A | Confirmed latest A2A | Probable | Negative |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| USA | 1000 | 2000 | 319 | 173 | 8 | 2 | 0 |

Notable confirmed latest `agent-card.json` examples:

- `Docs by LangChain`
- `Orin - Delegance Insurance Assistant`
- `three.ws`
- `Registry Ping Agent`
- `David YC Tseng`
- `Akemi`
- `Reswap`

The broad query found significantly more latest A2A cards than the previous well-known-only query, so it is useful for discovery. However, 1536 of 2000 card requests timed out with a 3 second timeout. Scanner implementation should keep high concurrency and bounded timeouts for this class of imported targets.

Interface probe results for confirmed cards:

| Endpoint probes | JSON-RPC method-not-found without auth | Auth required | A2A endpoint disabled | Network error | Other/unknown |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 182 | 164 | 4 | 6 | 2 | 6 |

Dominant cluster:

- `system-admin-agent`: 163 cards
- live no-auth JSON-RPC method-not-found: 161
- skills:
  - `schedule_system_update`
  - `schedule_system_commands`
  - `schedule_system_backup`

This cluster should be highlighted in terminal/HTML summaries because it combines:

- public A2A/legacy Agent Card
- no-auth JSON-RPC endpoint reachability
- dangerous system administration skills
- endpoint path `/a2a`

Exposure signals from this sample:

- `system_admin_skill_names`
- `no_auth_jsonrpc_method_not_found`
- `relative_a2a_endpoint`
- `official_agent_card`
- `auth_required_live_probe`

Output guidance:

- Do not emit `CRITICAL/HIGH/MEDIUM/LOW`.
- Do show counts for public cards, no-auth JSON-RPC endpoints, auth-required endpoints, disabled endpoints, private/localhost advertised endpoints, and notable skill keywords.

Recommended next Quake queries:

System-admin cluster:

```text
body="system-admin-agent" AND body="schedule_system_commands"
body="schedule_system_update" AND body="schedule_system_backup"
body="\"/a2a\"" AND body="schedule_system_commands"
```

Latest A2A cards:

```text
body="agent-card.json" AND body="skills" AND body="capabilities"
body="supportedInterfaces" AND body="protocolVersion" AND body="skills"
body="application/a2a+json" OR headers="A2A-Version"
```

No-auth endpoint candidates:

```text
body="\"url\":\"/a2a\"" AND body="skills" AND body="capabilities"
body="\"url\": \"/a2a\"" AND body="skills" AND body="capabilities"
body="\"/api/a2a\"" AND body="skills" AND body="capabilities"
```

## Data Model Additions

Add protocol-neutral result support instead of overloading `MCPServer`:

- `models.ProtocolResult`
  - `protocol`: `mcp` or `a2a`
  - common network fields: IP, port, hostname, URL, endpoint, TLS, scan time
  - `fingerprint_score`, `exposure_status`
  - `no_auth`, `auth_required`
  - `evidence`

Short-term, to minimize churn, add `A2AServer` and make output support a mixed result wrapper:

- `models.A2AServer`
  - `AgentName`, `Description`, `Provider`, `Version`
  - `CardURL`, `InterfaceURLs`
  - `Capabilities`
  - `SecuritySchemes`, `Security`
  - `Skills`, `SkillCount`
  - `Signatures`
  - `ExposureSignals`, `ExposureStatus`
  - `Evidence`

Recommended files:

- `pkg/models/a2a.go`
- `pkg/scanner/a2a_probe.go`
- `pkg/scanner/a2a_exposure.go`
- `pkg/scanner/a2a_probe_test.go`
- `testservers/a2a_*.py`

## CLI Plan

Add a first-class subcommand:

```bash
agentscan a2a <targets...>
agentscan scan <targets...>   # runs MCP + A2A
```

Flags:

- `--a2a-threads N`: default 50.
- `--include-probable`: include probable A2A matches below confirmed threshold.
- `--active-a2a`: future flag, disabled initially; required before any task creation or push notification config.
- Reuse `--skip-port-scan`, `--ports`, `--timeout`, `--format`, `--output`, `--verbose`, `--no-color`.

## Implementation Tasks

1. Add A2A models and JSON output support.
2. Add card discovery paths to config.
3. Implement `ProbeA2AWithHostname(ctx, baseURL, hostname, urlPath, timeoutMs)`.
4. Implement Agent Card scoring and ACP exclusion heuristics.
5. Implement JSON-RPC unknown-method no-auth/auth-required probe for selected JSON-RPC interfaces.
6. Implement extended-card no-auth check, still read-only.
7. Add exposure signal extraction from card content, auth posture, TLS, signatures, and skill keywords.
8. Add `a2a` CLI command.
9. Update `scan` to run all selected protocol scanners and merge output.
10. Add test servers:
    - safe public card with OAuth required.
    - no-auth JSON-RPC interface with harmless error response.
    - extended card exposed without auth.
    - ACP-like `agent.json` false positive.
    - card with credential-like text and private endpoints.

## First Milestone Acceptance Criteria

- `agentscan a2a http://127.0.0.1:PORT --skip-port-scan --format json` detects valid Agent Cards.
- It never sends `SendMessage`, `CancelTask`, or push notification config methods.
- It reports card metadata, skills, auth posture, signatures, and evidence.
- It distinguishes A2A `agent-card.json` from ACP-style `agent.json`.
- Existing MCP tests still pass unchanged.

## Open Questions

- Whether to make a protocol-neutral result schema now or defer until ACP support.
- Whether to support gRPC reflection/probing in v1; recommended answer is no for first milestone.
- Whether to add signature verification in v1; recommended answer is record presence first, verify later with explicit JWKS retrieval limits.
- Whether public card fetching should follow redirects cross-host; recommended answer is same-host only by default.
