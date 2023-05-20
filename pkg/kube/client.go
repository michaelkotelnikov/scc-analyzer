package kube

import (
	"context"
	"fmt"

	openshiftsecurityv1 "github.com/openshift/api/security/v1"
	securityv1 "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	KubeClient *clientset.Clientset

	SecurityV1Client *securityv1.SecurityV1Client

	ListOptions metav1.ListOptions
}

func NewClient(context string) (*Client, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	configOverrides := &clientcmd.ConfigOverrides{
		CurrentContext: context,
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve client configuration: %w", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate Kubernetes client: %w", err)
	}

	sClient, err := securityv1.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate OpenShift Security client: %w", err)
	}

	listOptions := metav1.ListOptions{
		TypeMeta: metav1.TypeMeta{
			Kind:       "",
			APIVersion: "v1",
		},
		LabelSelector:        "",
		FieldSelector:        "",
		Watch:                false,
		AllowWatchBookmarks:  false,
		ResourceVersion:      "",
		ResourceVersionMatch: "",
		TimeoutSeconds:       nil,
		Limit:                0,
		Continue:             "",
	}

	return &Client{
		KubeClient:       client,
		SecurityV1Client: sClient,
		ListOptions:      listOptions,
	}, nil
}

func (client *Client) GetClusterRoleBindings() ([]rbacv1.ClusterRoleBinding, error) {
	list, err := client.KubeClient.RbacV1().ClusterRoleBindings().List(context.TODO(), client.ListOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ClusterRoleBindings from Kubernetes client: %w", err)
	}

	return list.Items, nil
}

func (client *Client) GetClusterRoles() ([]rbacv1.ClusterRole, error) {
	list, err := client.KubeClient.RbacV1().ClusterRoles().List(context.TODO(), client.ListOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ClusterRoles from Kubernetes client: %w", err)
	}

	return list.Items, nil
}

func (client *Client) GetServiceAccounts(namespace string) ([]v1.ServiceAccount, error) {
	list, err := client.KubeClient.CoreV1().ServiceAccounts(namespace).List(context.TODO(), client.ListOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ServiceAccounts from Kubernetes client: %w", err)
	}

	return list.Items, nil
}

func (client *Client) GetSecurityContextConstraints() ([]openshiftsecurityv1.SecurityContextConstraints, error) {
	list, err := client.SecurityV1Client.SecurityContextConstraints().List(context.TODO(), client.ListOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SecurityContextConstraints from OpenShift Security client: %w", err)
	}

	return list.Items, nil
}
