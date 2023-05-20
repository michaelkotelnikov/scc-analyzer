package analyzer

import (
	"reflect"
	"strconv"
	"strings"

	openshiftsecurityv1 "github.com/openshift/api/security/v1"
)

type Rules struct {
	boolRules map[string]bool
	typeRules map[string]string
	listRules map[string][]string
}

func BuildRules() *Rules {
	rules := &Rules{}

	rules.boolRules = make(map[string]bool)
	rules.typeRules = make(map[string]string)
	rules.listRules = make(map[string][]string)

	rules.boolRules["allowHostIPC"] = false
	rules.boolRules["allowHostNetwork"] = false
	rules.boolRules["allowPrivilegedContainer"] = false

	rules.typeRules["runAsUser"] = "MustRunAsRange"
	rules.typeRules["seLinuxContext"] = "MustRunAs"
	rules.typeRules["fsGroup"] = "MustRunAs"

	rules.listRules["volumes"] = append(rules.listRules["volumes"],
		"configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret")
	rules.listRules["allowedCapabilities"] = append(rules.listRules["allowedCapabilities"], "NET_BIND_SERVICE")

	return rules
}

func (rules *Rules) EvaluateSCC(scc *openshiftsecurityv1.SecurityContextConstraints) map[string]string {
	sccEvaluation := make(map[string]string)

	rules.EvaluateTypes(&sccEvaluation, scc)
	rules.EvaluateBools(&sccEvaluation, scc)
	rules.EvaluateLists(&sccEvaluation, scc)

	return sccEvaluation
}

func (rules *Rules) EvaluateLists(evaluation *map[string]string,
	scc *openshiftsecurityv1.SecurityContextConstraints) {
	for rule := range rules.listRules {
		var violatingItems []string
		field := reflect.ValueOf(scc).Elem().FieldByNameFunc(func(fieldName string) bool {
			return strings.EqualFold(fieldName, rule)
		})
		if field.IsValid() {
			if field.Kind() == reflect.Slice {
				sccItems := make([]string, field.Len())
				for i := 0; i < field.Len(); i++ {
					sccItems[i] = field.Index(i).String()
				}
				violation := false
				for _, sccItem := range sccItems {
					for _, listItem := range rules.listRules[rule] {
						if listItem == sccItem {
							violation = false
							break
						}
						violation = true
					}
					if violation {
						violatingItems = append(violatingItems, sccItem)
					}
				}
				if len(violatingItems) > 0 {
					violatingString := strings.Join(violatingItems, ", ")
					msg := rule + ": [" + violatingString + "]"
					(*evaluation)[rule] = msg
				}
			}
		}
	}
}

func (rules *Rules) EvaluateTypes(evaluation *map[string]string,
	scc *openshiftsecurityv1.SecurityContextConstraints) {
	for rule := range rules.typeRules {
		field := reflect.ValueOf(scc).Elem().FieldByNameFunc(func(fieldName string) bool {
			return strings.EqualFold(fieldName, rule)
		})
		if field.IsValid() {
			fieldValue := field.FieldByName("Type")
			if fieldValue.IsValid() {
				value := fieldValue.String()
				if strings.ToLower(value) != strings.ToLower((rules.typeRules)[rule]) {
					msg := rule + ".type: " + value
					(*evaluation)[rule] = msg
				}
			}
		}
	}
}

func (rules *Rules) EvaluateBools(evaluation *map[string]string,
	scc *openshiftsecurityv1.SecurityContextConstraints) {
	for rule := range rules.boolRules {
		field := reflect.ValueOf(scc).Elem().FieldByNameFunc(func(fieldName string) bool {
			return strings.EqualFold(fieldName, rule)
		})
		if field.IsValid() {
			value := field.Bool()
			if value != rules.boolRules[rule] {
				msg := rule + ": " + strconv.FormatBool(value)
				(*evaluation)[rule] = msg
			}
		}
	}
}
