// Package output defines the auditable, structured result type that every
// RouteWarden rule produces. Rule R6 requires every finding to carry file,
// line, risk, CWE, reason, and confidence — never a silent detection.
package output

// Risk classifies how severe a Finding is. HIGH findings come from
// deterministic Go rules (rule R3); MEDIUM findings are the ones eligible
// for LLM triage in a future phase, out of scope for this build.
type Risk string

const (
	RiskHigh   Risk = "HIGH"
	RiskMedium Risk = "MEDIUM"
	RiskClean  Risk = "CLEAN"
)

// Finding is a single, structured security observation about a line of
// code. This is the only thing a rule is allowed to produce, and it is
// exactly what gets turned into a GitHub PR review comment (rule R1).
type Finding struct {
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Risk       Risk    `json:"risk"`
	CWE        string  `json:"cwe"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}
