package analyzer

import (
	openshiftsecurityv1 "github.com/openshift/api/security/v1"
	v1 "k8s.io/api/core/v1"
)

type ServiceAccountSCC struct {
	ServiceAccount v1.ServiceAccount

	SecurityContextConstraints []openshiftsecurityv1.SecurityContextConstraints
}

func CreateServiceAccountMap(permissions *Permissions, sa v1.ServiceAccount) *ServiceAccountSCC {
	serviceAccountSCC := &ServiceAccountSCC{
		ServiceAccount:             sa,
		SecurityContextConstraints: make([]openshiftsecurityv1.SecurityContextConstraints, 0),
	}

	serviceAccountSCC.BuildSCCByRole(permissions)
	serviceAccountSCC.BuildSCCByUser(permissions)

	serviceAccountSCC.RemoveDuplicateSCCs()

	return serviceAccountSCC
}

func (sas *ServiceAccountSCC) BuildSCCByRole(permissions *Permissions) {
	var usedSCCNames []string

	serviceAccountClusterRoles := permissions.BuildServiceAccountClusterRoles(sas.ServiceAccount)

	for _, clusterRole := range serviceAccountClusterRoles {
		for _, rule := range clusterRole.Rules {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					if verb == "use" && resource == "securitycontextconstraints" {
						usedSCCNames = append(usedSCCNames, rule.ResourceNames...)
					}
				}
			}
		}
	}

	for _, scc := range permissions.SecurityContextConstraints {
		for _, sccName := range usedSCCNames {
			if scc.Name == sccName {
				sas.SecurityContextConstraints = append(sas.SecurityContextConstraints, scc)
			}
		}
	}
}

func (sas *ServiceAccountSCC) BuildSCCByUser(permissions *Permissions) {
	saString := "system:serviceaccount:" + sas.ServiceAccount.Namespace + ":" + sas.ServiceAccount.Name

	for _, scc := range permissions.SecurityContextConstraints {
		for _, user := range scc.Users {
			if user == saString {
				sas.SecurityContextConstraints = append(sas.SecurityContextConstraints, scc)
			}
		}
	}
}

func (sas *ServiceAccountSCC) RemoveDuplicateSCCs() {
	allKeys := make(map[string]bool)
	list := []openshiftsecurityv1.SecurityContextConstraints{}

	for _, scc := range sas.SecurityContextConstraints {
		if _, value := allKeys[scc.Name]; !value {
			allKeys[scc.Name] = true

			list = append(list, scc)
		}
	}

	sas.SecurityContextConstraints = list
}
