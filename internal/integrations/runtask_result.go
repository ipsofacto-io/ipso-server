package integrations

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/ipsofacto-io/ipso/pkg/plancheck"
)

const (
	jsonAPI = "application/vnd.api+json"
	// Limits that keep a document inside the 5 MB HCP Terraform accepts, with 2.5 MB to spare.
	maxRunTaskOutcomes = 100
	maxOutcomeAddrs    = 50
	maxAddressBytes    = 512
)

// taskResult is what one run reports. It carries verdicts and resource addresses. It carries no
// violation message, because a message can quote an attribute the run's readers cannot see (ADR-0065).
type taskResult struct {
	status     string
	message    string
	outcomes   []taskOutcome
	planSHA256 string
	checks     int
	failed     int
}

type taskOutcome struct {
	id          string
	description string
	body        string
	statusLabel string
	statusLevel string
	severity    string
	level       string
}

// resultOf applies the rule of exit 1: the run fails when the report blocks, and warnings pass.
func resultOf(report plancheck.Report, withOutcomes bool) taskResult {
	result := taskResult{status: statusPassed, planSHA256: report.PlanSHA256, checks: len(report.Verdicts)}
	if report.Blocked {
		result.status = statusFailed
	}
	var blocking, warnings, waived, errored, passed int
	for _, verdict := range report.Verdicts {
		switch verdict.Result {
		case plancheck.ResultFail:
			result.failed++
			if verdict.Mode == "block" {
				blocking++
			} else {
				warnings++
			}
		case plancheck.ResultWaived:
			waived++
		case plancheck.ResultError:
			errored++
		default:
			passed++
		}
		if withOutcomes && verdict.Result != plancheck.ResultPass {
			result.outcomes = append(result.outcomes, outcomeOf(verdict))
		}
	}
	result.message = summaryOf(blocking, errored, warnings, waived, passed)
	if len(result.outcomes) > maxRunTaskOutcomes {
		left := len(result.outcomes) - maxRunTaskOutcomes
		result.outcomes = result.outcomes[:maxRunTaskOutcomes]
		result.message += fmt.Sprintf(" %d more checks are not listed.", left)
	}
	return result
}

func summaryOf(blocking, errored, warnings, waived, passed int) string {
	if blocking+errored+warnings+waived+passed == 0 {
		return "ipso: no checks selected."
	}
	return fmt.Sprintf("ipso: %d blocking, %d could not be evaluated, %d warnings, %d waived, %d passed.", blocking, errored, warnings, waived, passed)
}

func outcomeOf(verdict plancheck.Verdict) taskOutcome {
	outcome := taskOutcome{
		id:          fmt.Sprintf("%s/%d", verdict.DecisionID, verdict.CheckIndex),
		description: fmt.Sprintf("%s: checks[%d]", cleanText(verdict.Slug), verdict.CheckIndex),
	}
	switch {
	case verdict.Result == plancheck.ResultError:
		outcome.statusLabel, outcome.statusLevel = "Error", "error"
		outcome.severity, outcome.level = "Blocking", "error"
		outcome.body = "ipso could not evaluate this check, so it blocks."
	case verdict.Result == plancheck.ResultWaived:
		outcome.statusLabel, outcome.statusLevel = "Waived", "info"
		outcome.severity, outcome.level = modeLabel(verdict.Mode), "info"
		outcome.body = fmt.Sprintf("A waiver or a baseline covers %d violations.", verdict.Count)
	case verdict.Mode == "block":
		outcome.statusLabel, outcome.statusLevel = "Failed", "error"
		outcome.severity, outcome.level = modeLabel(verdict.Mode), "error"
		outcome.body = addressBody(verdict)
	case verdict.Mode == "warn":
		outcome.statusLabel, outcome.statusLevel = "Warning", "warning"
		outcome.severity, outcome.level = modeLabel(verdict.Mode), "warning"
		outcome.body = addressBody(verdict)
	default:
		outcome.statusLabel, outcome.statusLevel = "Advisory", "info"
		outcome.severity, outcome.level = modeLabel(verdict.Mode), "info"
		outcome.body = addressBody(verdict)
	}
	return outcome
}

func modeLabel(mode string) string {
	switch mode {
	case "block":
		return "Blocking"
	case "warn":
		return "Warning"
	default:
		return "Advisory"
	}
}

// addressBody lists the resources of a failed check inside a code block, so an address cannot format
// the page. A denial with no address is only counted.
func addressBody(verdict plancheck.Verdict) string {
	var addresses []string
	for _, violation := range verdict.Violations {
		if violation.Address != "" {
			addresses = append(addresses, cleanText(violation.Address))
		}
	}
	var body strings.Builder
	fmt.Fprintf(&body, "%d violations. Run `ipso check plan` on this plan to read the messages.\n", verdict.Count)
	if len(addresses) == 0 {
		return body.String()
	}
	shown := addresses
	if len(shown) > maxOutcomeAddrs {
		shown = shown[:maxOutcomeAddrs]
	}
	body.WriteString("\n```text\n")
	for _, address := range shown {
		body.WriteString(address)
		body.WriteByte('\n')
	}
	body.WriteString("```\n")
	if left := len(addresses) - len(shown); left > 0 {
		fmt.Fprintf(&body, "\n%d more are not listed.\n", left)
	}
	return body.String()
}

// cleanText keeps text on one line, out of a Markdown code fence's reach, and within a size.
func cleanText(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		if r == '`' {
			return '\''
		}
		return r
	}, value)
	if len(cleaned) > maxAddressBytes {
		return strings.ToValidUTF8(cleaned[:maxAddressBytes], "")
	}
	return cleaned
}

// document is the JSON:API body of the callback.
func (r taskResult) document() map[string]any {
	data := map[string]any{
		"type": "task-results",
		"attributes": map[string]any{
			"status":  r.status,
			"message": r.message,
		},
	}
	if len(r.outcomes) > 0 {
		outcomes := make([]map[string]any, 0, len(r.outcomes))
		for _, outcome := range r.outcomes {
			outcomes = append(outcomes, map[string]any{
				"type": "task-result-outcomes",
				"attributes": map[string]any{
					"outcome-id":  outcome.id,
					"description": outcome.description,
					"body":        outcome.body,
					"tags": map[string]any{
						"Status":   []map[string]string{{"label": outcome.statusLabel, "level": outcome.statusLevel}},
						"Severity": []map[string]string{{"label": outcome.severity, "level": outcome.level}},
					},
				},
			})
		}
		data["relationships"] = map[string]any{"outcomes": map[string]any{"data": outcomes}}
	}
	return map[string]any{"data": data}
}
