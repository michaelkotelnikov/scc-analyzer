package analyzer

import (
	"reflect"
	"strconv"
	"strings"

	openshiftsecurityv1 "github.com/openshift/api/security/v1"
)

type Rule struct {
	Field string
	Value interface{}
}

type Rules struct {
	BoolRules []Rule
	TypeRules []Rule
	ListRules []Rule
}

func BuildRules() *Rules {
	rules := &Rules{}

	rules.BoolRules = []Rule{
		{Field: "allowHostIPC", Value: false},
		{Field: "allowHostNetwork", Value: false},
		{Field: "allowPrivilegedContainer", Value: false},
		{Field: "allowHostDirVolumePlugin", Value: false},
		{Field: "allowHostPID", Value: false},
		{Field: "allowHostPorts", Value: false},
		{Field: "allowPrivilegeEscalation", Value: false},
	}

	rules.TypeRules = []Rule{
		{Field: "runAsUser", Value: "MustRunAsRange"},
		{Field: "seLinuxContext", Value: "MustRunAs"},
		{Field: "fsGroup", Value: "MustRunAs"},
	}

	rules.ListRules = []Rule{
		{Field: "volumes", Value: []string{
			"configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret",
		}},
		{Field: "allowedCapabilities", Value: []string{
			"NET_BIND_SERVICE",
		}},
	}

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
	for _, rule := range rules.ListRules {
		var violatingItems []string

		field := reflect.ValueOf(scc).Elem().FieldByNameFunc(func(fieldName string) bool {
			return strings.EqualFold(fieldName, rule.Field)
		})
		if field.IsValid() {
			if field.Kind() == reflect.Slice {
				sccItems := make([]string, field.Len())
				for i := 0; i < field.Len(); i++ {
					sccItems[i] = field.Index(i).String()
				}

				violation := false

				for _, sccItem := range sccItems {
					if ruleValues, ok := rule.Value.([]string); ok {
						for _, listItem := range ruleValues {
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
				}

				if len(violatingItems) > 0 {
					violatingString := strings.Join(violatingItems, ", ")
					msg := rule.Field + ": [" + violatingString + "]"
					(*evaluation)[rule.Field] = msg
				}
			}
		}
	}
}

func (rules *Rules) EvaluateTypes(evaluation *map[string]string,
	scc *openshiftsecurityv1.SecurityContextConstraints) {
	for _, rule := range rules.TypeRules {
		field := reflect.ValueOf(scc).Elem().FieldByNameFunc(func(fieldName string) bool {
			return strings.EqualFold(fieldName, rule.Field)
		})
		if field.IsValid() {
			fieldValue := field.FieldByName("Type")
			if fieldValue.IsValid() {
				value := fieldValue.String()
				if ruleValue, ok := rule.Value.(string); ok {
					if !strings.EqualFold(value, ruleValue) {
						msg := rule.Field + ".type: " + value
						(*evaluation)[rule.Field] = msg
					}
				}
			}
		}
	}
}

func (rules *Rules) EvaluateBools(evaluation *map[string]string,
	scc *openshiftsecurityv1.SecurityContextConstraints) {
	for _, rule := range rules.BoolRules {
		field := reflect.ValueOf(scc).Elem().FieldByNameFunc(func(fieldName string) bool {
			return strings.EqualFold(fieldName, rule.Field)
		})
		if field.IsValid() {
			var value bool
			if field.Kind() == reflect.Bool {
				value = field.Bool()
			} else if field.Kind() == reflect.Ptr && field.Type().Elem().Kind() == reflect.Bool {
				if field.IsNil() {
					continue
				}
				value = field.Elem().Bool()
			}

			if ruleValue, ok := rule.Value.(bool); ok {
				if value != ruleValue {
					msg := rule.Field + ": " + strconv.FormatBool(value)
					(*evaluation)[rule.Field] = msg
				}
			}
		}
	}
}
