package podcache

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/example/ebpf-dns-latency-monitor/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type Cache struct {
	mu   sync.RWMutex
	pods map[string]model.PodRef
}

func New() *Cache {
	return &Cache{pods: map[string]model.PodRef{}}
}

func (c *Cache) Lookup(ip string) model.PodRef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if p, ok := c.pods[ip]; ok {
		return p
	}
	return model.PodRef{Namespace: "unknown", Name: "unknown", IP: ip}
}

func (c *Cache) set(ip string, ref model.PodRef) {
	if ip == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pods[ip] = ref
}

func (c *Cache) delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pods, ip)
}

func (c *Cache) Run(ctx context.Context, kubeconfig string) error {
	cfg, err := kubeConfig(kubeconfig)
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	factory := informers.NewSharedInformerFactory(client, 30*time.Second)
	inf := factory.Core().V1().Pods().Informer()
	_, err = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.upsertPod(obj) },
		UpdateFunc: func(_, newObj any) { c.upsertPod(newObj) },
		DeleteFunc: func(obj any) { c.removePod(obj) },
	})
	if err != nil {
		return err
	}
	factory.Start(ctx.Done())
	for typ, ok := range factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			slog.Warn("pod informer cache failed to sync", "type", typ.String())
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (c *Cache) upsertPod(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Status.PodIP == "" {
		return
	}
	c.set(pod.Status.PodIP, model.PodRef{Namespace: pod.Namespace, Name: pod.Name, NodeName: pod.Spec.NodeName, IP: pod.Status.PodIP})
	for _, ip := range pod.Status.PodIPs {
		c.set(ip.IP, model.PodRef{Namespace: pod.Namespace, Name: pod.Name, NodeName: pod.Spec.NodeName, IP: ip.IP})
	}
}

func (c *Cache) removePod(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			pod, _ = tombstone.Obj.(*corev1.Pod)
		}
	}
	if pod == nil {
		return
	}
	c.delete(pod.Status.PodIP)
	for _, ip := range pod.Status.PodIPs {
		c.delete(ip.IP)
	}
}

func kubeConfig(path string) (*rest.Config, error) {
	if path != "" {
		return clientcmd.BuildConfigFromFlags("", path)
	}
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
}

func PrimeOnce(ctx context.Context, kubeconfig string, c *Cache) error {
	cfg, err := kubeConfig(kubeconfig)
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		c.upsertPod(p)
	}
	return nil
}
