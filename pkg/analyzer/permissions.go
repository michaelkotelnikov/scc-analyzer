package analyzer

import (
	"fmt"

	"github.com/michaelkotelnikov/scc-analyzer/scc-analyzer/pkg/kube"

	openshiftsecurityv1 "github.com/openshift/api/security/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

type Permissions struct {
	Namespace string

	ServiceAccounts []v1.ServiceAccount

	ClusterRoles        []rbacv1.ClusterRole
	ClusterRoleBindings []rbacv1.ClusterRoleBinding

	SecurityContextConstraints []openshiftsecurityv1.SecurityContextConstraints
}

func BuildPermissions(client *kube.Client, namespace string) (*Permissions, error) {
	permissions := &Permissions{
		Namespace:                  namespace,
		ServiceAccounts:            make([]v1.ServiceAccount, 0),
		ClusterRoles:               make([]rbacv1.ClusterRole, 0),
		ClusterRoleBindings:        make([]rbacv1.ClusterRoleBinding, 0),
		SecurityContextConstraints: make([]openshiftsecurityv1.SecurityContextConstraints, 0),
	}

	sas, err := client.GetServiceAccounts(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ServiceAccounts: %w", err)
	}

	permissions.ServiceAccounts = sas

	crs, err := client.GetClusterRoles()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ClusterRoles: %w", err)
	}

	permissions.ClusterRoles = crs

	crbs, err := client.GetClusterRoleBindings()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ClusterRoleBindings: %w", err)
	}

	permissions.ClusterRoleBindings = crbs

	sccs, err := client.GetSecurityContextConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SecurityContextConstraints: %w", err)
	}

	permissions.SecurityContextConstraints = sccs

	return permissions, nil
}

func (permissions *Permissions) BuildServiceAccountClusterRoles(sa v1.ServiceAccount) []rbacv1.ClusterRole {
	var serviceAccountPermissions []rbacv1.ClusterRole

	for _, crb := range permissions.ClusterRoleBindings {
		for _, subject := range crb.Subjects {
			if subject.Name == sa.Name && subject.Namespace == sa.Namespace {
				for _, cr := range permissions.ClusterRoles {
					if crb.RoleRef.Name == cr.Name {
						serviceAccountPermissions = append(serviceAccountPermissions, cr)
					}
				}
			}
		}
	}

	return serviceAccountPermissions
}
