// Copyright Jetstack Ltd. See LICENSE for details.
package kind

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	configv1alpha4 "sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
)

const (
	clusterName = "kube-oidc-proxy-e2e"

	// ProxyNodePort is the fixed NodePort assigned to the proxy Service. It is
	// mapped to the same port on 127.0.0.1 of the host via the kind node's
	// extraPortMappings (see New), so the suite reaches the proxy at
	// https://127.0.0.1:<ProxyNodePort>. This keeps the host->proxy network path
	// identical on Linux (CI) and macOS, where the kind node's InternalIP sits on
	// a docker bridge network that is not routable from the host.
	ProxyNodePort = 31443
)

type Kind struct {
	rootPath  string
	nodeImage string
	conf      *configv1alpha4.Cluster

	provider   *cluster.Provider
	restConfig *rest.Config
	client     *kubernetes.Clientset
}

func New(rootPath, nodeImage string, masterNodes, workerNodes int) *Kind {
	conf := new(configv1alpha4.Cluster)
	configv1alpha4.SetDefaultsCluster(conf)
	conf.Nodes = nil

	// This behviour will be changing soon in later versions of kind.
	if workerNodes == 0 {
		for i := 0; i < masterNodes; i++ {
			conf.Nodes = append(conf.Nodes,
				configv1alpha4.Node{
					Image: nodeImage,
				})
		}

	} else {
		for i := 0; i < masterNodes; i++ {
			conf.Nodes = append(conf.Nodes,
				configv1alpha4.Node{
					Image: nodeImage,
					Role:  configv1alpha4.ControlPlaneRole,
				})
		}

		for i := 0; i < workerNodes; i++ {
			conf.Nodes = append(conf.Nodes,
				configv1alpha4.Node{
					Image: nodeImage,
					Role:  configv1alpha4.WorkerRole,
				})
		}
	}

	conf.Networking.ServiceSubnet = "10.0.0.0/16"

	// Map the proxy's fixed NodePort to the same host port on 127.0.0.1 so the
	// test process (running on the host) can reach the proxy Service without
	// depending on the kind node IP being routable from the host. Mapped on a
	// single node only to avoid a host-port collision across node containers.
	if len(conf.Nodes) > 0 {
		conf.Nodes[0].ExtraPortMappings = append(conf.Nodes[0].ExtraPortMappings,
			configv1alpha4.PortMapping{
				ContainerPort: ProxyNodePort,
				HostPort:      ProxyNodePort,
				ListenAddress: "127.0.0.1",
				Protocol:      configv1alpha4.PortMappingProtocolTCP,
			})
	}

	return &Kind{
		rootPath:  rootPath,
		nodeImage: nodeImage,
		conf:      conf,
	}
}

func (k *Kind) Create() error {
	slog.Info("kind: using node image", slog.String("image", k.nodeImage))

	// create kind cluster
	slog.Info("kind: creating cluster", slog.String("cluster", clusterName))
	k.provider = cluster.NewProvider()
	if err := k.provider.Create(
		clusterName,
		cluster.CreateWithV1Alpha4Config(k.conf),
	); err != nil {
		return err
	}

	// generate rest config to kind cluster
	kubeconfigData, err := k.provider.KubeConfig(clusterName, false)
	if err != nil {
		return err
	}

	if err := os.WriteFile(k.KubeConfigPath(), []byte(kubeconfigData), 0600); err != nil {
		return err
	}

	restConfig, err := clientcmd.BuildConfigFromFlags("", k.KubeConfigPath())
	if err != nil {
		return k.errDestroy(fmt.Errorf("failed to build kind rest client: %w", err))
	}
	k.restConfig = restConfig

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return k.errDestroy(fmt.Errorf("failed to build kind kubernetes client: %w", err))
	}
	k.client = client

	if err := k.waitForNodesReady(); err != nil {
		return k.errDestroy(fmt.Errorf("failed to wait for nodes to become ready: %w", err))
	}

	if err := k.waitForCoreDNSReady(); err != nil {
		return k.errDestroy(fmt.Errorf("failed to wait for DNS pods to become ready: %w", err))
	}

	slog.Info("kind: cluster ready", slog.String("cluster", clusterName))

	return nil
}

// DeleteCluster deletes the named kind cluster. It writes the cluster's
// kubeconfig to a throwaway temp file (rather than mutating the caller's real
// kubeconfig) that kind uses to remove the cluster's context, and always
// cleans that file up.
func DeleteCluster(name string) error {
	provider := cluster.NewProvider()

	f, err := os.CreateTemp("", name)
	if err != nil {
		return fmt.Errorf("failed to create temp kubeconfig for cluster %q: %w", name, err)
	}
	// Remove the throwaway kubeconfig on every path, success or error.
	defer func() {
		if rmErr := os.Remove(f.Name()); rmErr != nil && !os.IsNotExist(rmErr) {
			slog.Error("kind: failed to remove temp kubeconfig", slog.String("path", f.Name()), slog.Any("error", rmErr))
		}
	}()

	kubeconfig, err := provider.KubeConfig(name, false)
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to get kubeconfig for cluster %q: %w", name, err)
	}

	if _, err := f.Write([]byte(kubeconfig)); err != nil {
		f.Close()
		return fmt.Errorf("failed to write temp kubeconfig for cluster %q: %w", name, err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp kubeconfig for cluster %q: %w", name, err)
	}

	if err := provider.Delete(name, f.Name()); err != nil {
		return fmt.Errorf("failed to delete cluster %q: %w", name, err)
	}

	return nil
}

func (k *Kind) Destroy() error {
	if err := k.collectLogs(); err != nil {
		// Don't hard fail here as we should still attempt to delete the cluster
		slog.Error("kind: failed to collect logs", slog.Any("error", err))
	}

	slog.Info("kind: destroying cluster", slog.String("cluster", clusterName))

	if err := DeleteCluster(clusterName); err != nil {
		return fmt.Errorf("failed to delete kind cluster: %w", err)
	}

	if err := os.Remove(k.KubeConfigPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete kubeconfig file: %w", err)
	}

	slog.Info("kind: destroyed cluster", slog.String("cluster", clusterName))

	return nil
}

func (k *Kind) collectLogs() error {
	provider := cluster.NewProvider()
	logDir := filepath.Join(k.rootPath, "artifacts", "logs")

	slog.Info("kind: collecting logs", slog.String("dir", logDir))

	if err := os.RemoveAll(logDir); err != nil {
		return fmt.Errorf("failed to remove old logs directory: %w", err)
	}

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	if err := provider.CollectLogs(clusterName, logDir); err != nil {
		return fmt.Errorf("failed to collect logs: %w", err)
	}

	slog.Info("kind: collected logs", slog.String("dir", logDir))

	return nil
}

func (k *Kind) KubeConfigPath() string {
	return filepath.Join(os.TempDir(), "kube-oidc-proxy-e2e")
}

func (k *Kind) Nodes() ([]nodes.Node, error) {
	if k.provider == nil {
		k.provider = cluster.NewProvider()
	}
	return k.provider.ListNodes(clusterName)
}

func (k *Kind) errDestroy(err error) error {
	if dErr := k.Destroy(); dErr != nil {
		err = fmt.Errorf("%w\nkind failed to destroy: %w", err, dErr)
	}

	return err
}

func (k *Kind) waitForNodesReady() error {
	slog.Info("kind: waiting for all nodes to become ready")

	return wait.PollUntilContextTimeout(context.Background(), time.Second*5, time.Minute*10, true, func(ctx context.Context) (bool, error) {
		nodes, err := k.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(nodes.Items) == 0 {
			slog.Warn("kind: no nodes found, checking again")
			return false, nil
		}

		var notReady []string
		for _, node := range nodes.Items {
			var ready bool
			for _, c := range node.Status.Conditions {
				if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}

			if !ready {
				notReady = append(notReady, node.Name)
			}
		}

		if len(notReady) > 0 {
			slog.Info("kind: nodes not ready",
				slog.String("nodes", strings.Join(notReady, ", ")))
			return false, nil
		}

		return true, nil
	})
}

func (k *Kind) waitForCoreDNSReady() error {
	slog.Info("kind: waiting for all DNS pods to become ready")
	return k.waitForPodsReady("kube-system", "k8s-app=kube-dns")
}

func (k *Kind) waitForPodsReady(namespace, labelSelector string) error {
	return wait.PollUntilContextTimeout(context.Background(), time.Second*5, time.Minute*10, true, func(ctx context.Context) (bool, error) {
		pods, err := k.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if err != nil {
			return false, err
		}

		if len(pods.Items) == 0 {
			slog.Warn("kind: no pods found, checking again",
				slog.String("namespace", namespace), slog.String("selector", labelSelector))
			return false, nil
		}

		var notReady []string
		for _, pod := range pods.Items {
			if pod.Status.Phase != corev1.PodRunning {
				notReady = append(notReady, fmt.Sprintf("%s:%s (%s)",
					pod.Namespace, pod.Name, pod.Status.Phase))
			}
		}

		if len(notReady) > 0 {
			slog.Info("kind: pods not ready",
				slog.String("pods", strings.Join(notReady, ", ")))
			return false, nil
		}

		return true, nil
	})
}
