// Copyright Jetstack Ltd. See LICENSE for details.

// Package appdeploy deploys the TLS-serving test apps (the mock OIDC issuer,
// the fake apiserver, the audit webhook and the proxy) as a Service, a Secret
// holding a freshly minted serving certificate, a ServiceAccount and a
// Deployment, all named after the app.
//
// The e2e helper and the metrics demo both deploy the mock issuer through it,
// so it takes a plain client and every image name and port as a parameter:
// depending on the e2e framework or test/kind would tie the demo to them.
package appdeploy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/rafpe/kube-oidc-proxy/test/util/keybundle"
)

// Port is the port every app serves TLS on, in its container and its Service.
const Port = 6443

// App describes one app to deploy. Its containers mount the serving
// certificate from the "tls" volume Create adds, as cert.pem and key.pem.
type App struct {
	Namespace, Name string

	// ServiceType is ClusterIP for an app reached from inside the cluster, or
	// NodePort for one reached from the host at https://127.0.0.1:NodePort.
	ServiceType corev1.ServiceType
	// NodePort pins the Service's node port of a NodePort app, so it lines up
	// with a port the cluster maps to the host. Ignored for ClusterIP.
	NodePort int32

	Containers []corev1.Container
	Volumes    []corev1.Volume
}

// Issuer returns the mock OIDC issuer app, running image as name in namespace
// and announcing its in-cluster Service URL as the issuer URL.
func Issuer(namespace, name, image string) App {
	return App{
		Namespace:   namespace,
		Name:        name,
		ServiceType: corev1.ServiceTypeClusterIP,
		Containers: []corev1.Container{{
			Name:            image,
			Image:           image,
			ImagePullPolicy: corev1.PullNever,
			Args: []string{
				"oidc-issuer",
				fmt.Sprintf("--secure-port=%d", Port),
				fmt.Sprintf("--issuer-url=https://%s:%d", serviceHost(namespace, name), Port),
				"--tls-cert-file=/tls/cert.pem",
				"--tls-private-key-file=/tls/key.pem",
			},
			VolumeMounts: []corev1.VolumeMount{{
				MountPath: "/tls",
				Name:      "tls",
				ReadOnly:  true,
			}},
			Ports: []corev1.ContainerPort{{ContainerPort: Port}},
		}},
	}
}

// Create creates app's objects and returns its serving certificate and the
// URL it is reached at. It does not wait for the app to serve.
func Create(ctx context.Context, client kubernetes.Interface, app App) (*keybundle.Bundle, *url.URL, error) {
	host := serviceHost(app.Namespace, app.Name)

	var netIPs []net.IP
	nodePort := int32(0)
	if app.ServiceType == corev1.ServiceTypeNodePort {
		// The app is reached from the host at https://127.0.0.1:<NodePort>, so
		// the serving certificate must cover 127.0.0.1 for the client's TLS
		// verification of that host to succeed.
		netIPs = append(netIPs, net.ParseIP("127.0.0.1"))
		nodePort = app.NodePort
	}

	keyBundle, err := keybundle.NewSelfSigned(host, netIPs, nil)
	if err != nil {
		return nil, nil, err
	}

	labels := map[string]string{"app": app.Name}
	meta := metav1.ObjectMeta{Name: app.Name, Namespace: app.Namespace}

	svc, err := client.CoreV1().Services(app.Namespace).Create(ctx, &corev1.Service{
		ObjectMeta: meta,
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{
				Port:       Port,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt(Port),
				NodePort:   nodePort,
			}},
			Type:     app.ServiceType,
			Selector: labels,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	appURL := fmt.Sprintf("https://%s:%d", host, Port)
	if len(netIPs) > 0 {
		appURL = fmt.Sprintf("https://%s:%s", netIPs[0],
			strconv.FormatUint(uint64(svc.Spec.Ports[0].NodePort), 10))
	}

	_, err = client.CoreV1().Secrets(app.Namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: meta,
		Data: map[string][]byte{
			"cert.pem": keyBundle.CertBytes,
			"key.pem":  keyBundle.KeyBytes,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	_, err = client.CoreV1().ServiceAccounts(app.Namespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: meta,
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	_, err = client.AppsV1().Deployments(app.Namespace).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: app.Name, Namespace: app.Namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: app.Name,
					Containers:         app.Containers,
					Volumes: append(app.Volumes, corev1.Volume{
						Name: "tls",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{SecretName: app.Name},
						},
					}),
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	appNetURL, err := url.Parse(appURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse app url %q: %w", appURL, err)
	}

	return keyBundle, appNetURL, nil
}

// Deploy creates app and waits until its Deployment is ready and its Service
// routes to it, which is when a ClusterIP app is reachable from inside the
// cluster. A NodePort app may still be unreachable from the host: kube-proxy
// programs that path after the endpoint turns ready.
func Deploy(ctx context.Context, client kubernetes.Interface, app App) (*keybundle.Bundle, *url.URL, error) {
	bundle, appURL, err := Create(ctx, client, app)
	if err != nil {
		return nil, nil, err
	}

	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
		return DeploymentReady(ctx, client, app.Namespace, app.Name)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("deployment %s/%s did not become ready: %w", app.Namespace, app.Name, err)
	}

	err = wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		return ServiceHasReadyEndpoint(ctx, client, app.Namespace, app.Name)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("service %s/%s has no ready endpoint: %w", app.Namespace, app.Name, err)
	}

	return bundle, appURL, nil
}

// DeploymentReady reports whether every desired replica of the Deployment is
// ready right now.
func DeploymentReady(ctx context.Context, client kubernetes.Interface, namespace, name string) (bool, error) {
	deploy, err := client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if deploy.Spec.Replicas == nil {
		return false, nil
	}

	return *deploy.Spec.Replicas == deploy.Status.ReadyReplicas, nil
}

// ServiceHasReadyEndpoint reports whether the Service has at least one ready
// endpoint, which is when its cluster DNS name starts routing to a pod. A ready
// Deployment alone does not mean that: the EndpointSlice controller publishes
// the pod as an endpoint asynchronously.
func ServiceHasReadyEndpoint(ctx context.Context, client kubernetes.Interface, namespace, service string) (bool, error) {
	list, err := client.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + service,
	})
	if err != nil {
		return false, err
	}

	for _, slice := range list.Items {
		for _, ep := range slice.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				return true, nil
			}
		}
	}

	return false, nil
}

func serviceHost(namespace, name string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)
}
