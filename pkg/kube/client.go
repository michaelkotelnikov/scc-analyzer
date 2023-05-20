package kube

import (
	"context"

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
}

func NewClient(context string) (*Client, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	configOverrides := &clientcmd.ConfigOverrides{
		CurrentContext: context,
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	kClient, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	sClient, err := securityv1.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{
		KubeClient:       kClient,
		SecurityV1Client: sClient,
	}, nil
}

func (client *Client) GetClusterRoleBindings() ([]rbacv1.ClusterRoleBinding, error) {
	list, err := client.KubeClient.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return list.Items, nil
}

func (client *Client) GetClusterRoles() ([]rbacv1.ClusterRole, error) {
	list, err := client.KubeClient.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return list.Items, nil
}

func (client *Client) GetServiceAccounts(namespace string) ([]v1.ServiceAccount, error) {
	list, err := client.KubeClient.CoreV1().ServiceAccounts(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return list.Items, nil
}

func (client *Client) GetSecurityContextConstraints() ([]openshiftsecurityv1.SecurityContextConstraints, error) {
	list, err := client.SecurityV1Client.SecurityContextConstraints().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return list.Items, nil
}
