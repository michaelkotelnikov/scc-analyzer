package analyzer

import (
	"strconv"

	openshiftsecurityv1 "github.com/openshift/api/security/v1"
)

type Rules struct {
	boolRules map[string]bool
	typeRules map[string]string
}

func BuildRules() *Rules {
	rules := &Rules{}

	rules.boolRules = make(map[string]bool)
	rules.typeRules = make(map[string]string)

	rules.boolRules["allowHostIPC"] = false
	rules.boolRules["allowHostNetwork"] = false

	rules.typeRules["runAsUser"] = "MustRunAsRange"

	return rules
}

func (rules *Rules) EvaluateSCC(scc *openshiftsecurityv1.SecurityContextConstraints) map[string]string {
	sccEvaluation := make(map[string]string)

	if scc.AllowHostIPC != rules.boolRules["allowHostIPC"] {
		msg := "'allowHostIPC: " + strconv.FormatBool(scc.AllowHostIPC) + "' is set. This setting allows containers to access the underlying host's IPC namespace."
		sccEvaluation["allowHostIPC"] = msg
	}

	if scc.AllowHostNetwork != rules.boolRules["allowHostNetwork"] {
		msg := "'allowHostNetwork: " + strconv.FormatBool(scc.AllowHostNetwork) + "' is set. This setting allows containers to access the underlying host's network namespace."
		sccEvaluation["allowHostNetwork"] = msg
	}

	if string(scc.RunAsUser.Type) != rules.typeRules["runAsUser"] {
		msg := "'runAsUser.type: " + string(scc.RunAsUser.Type) + "' is set. This setting allows containers to run as insecure UIDs on the underlying host."
		sccEvaluation["runAsUser"] = msg
	}

	return sccEvaluation
}
