package analyzer

import (
	openshiftsecurityv1 "github.com/openshift/api/security/v1"
	v1 "k8s.io/api/core/v1"
)

type ServiceAccountSCC struct {
	ServiceAccount v1.ServiceAccount

	SecurityContextConstraints []openshiftsecurityv1.SecurityContextConstraints
}

func CreateServiceAccountMap(p *Permissions, sa v1.ServiceAccount) *ServiceAccountSCC {
	serviceAccountSCC := &ServiceAccountSCC{}

	serviceAccountSCC.ServiceAccount = sa
	serviceAccountSCC.SecurityContextConstraints = make([]openshiftsecurityv1.SecurityContextConstraints, 0)

	serviceAccountSCC.BuildSCCByRole(p)
	serviceAccountSCC.BuildSCCByUser(p)

	serviceAccountSCC.RemoveDuplicateSCCs()

	return serviceAccountSCC
}

func (sas *ServiceAccountSCC) BuildSCCByRole(p *Permissions) {
	var usedSCCNames []string

	serviceAccountClusterRoles := p.BuildServiceAccountClusterRoles(sas.ServiceAccount)

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

	for _, scc := range p.SecurityContextConstraints {
		for _, sccName := range usedSCCNames {
			if scc.Name == sccName {
				sas.SecurityContextConstraints = append(sas.SecurityContextConstraints, scc)
			}
		}
	}
}

func (sas *ServiceAccountSCC) BuildSCCByUser(p *Permissions) {
	saString := "system:serviceaccount:" + sas.ServiceAccount.Namespace + ":" + sas.ServiceAccount.Name

	for _, scc := range p.SecurityContextConstraints {
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
