package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultRuntimeRemoteActionTimeout = 30 * time.Second
	runtimeSourceSystem               = "runtime_response"
	runtimeSourceActor                = "cerebro"
)

const (
	runtimeToolKillProcess       = "security.runtime.kill_process"
	runtimeToolIsolateContainer  = "security.runtime.isolate_container"
	runtimeToolIsolateHost       = "security.runtime.isolate_host"
	runtimeToolQuarantineFile    = "security.runtime.quarantine_file"
	runtimeToolBlockIP           = "security.runtime.block_ip"
	runtimeToolBlockDomain       = "security.runtime.block_domain"
	runtimeToolRevokeCredentials = "security.runtime.revoke_credentials"
	runtimeToolScaleDown         = "security.runtime.scale_down"
)

type RemoteActionCaller interface {
	CallTool(ctx context.Context, toolName string, args json.RawMessage, timeout time.Duration) (string, error)
}

type WorkloadScaler interface {
	ScaleDown(ctx context.Context, target WorkloadTarget, replicas int) error
}

type WorkloadTarget struct {
	Kind      string
	Namespace string
	Name      string
}

func (t WorkloadTarget) String() string {
	if t.Namespace == "" {
		return fmt.Sprintf("%s:%s", t.Kind, t.Name)
	}
	return fmt.Sprintf("%s:%s/%s", t.Kind, t.Namespace, t.Name)
}

type ActionCapabilityError struct {
	Action  ResponseActionType
	Code    string
	Message string
}

func (e *ActionCapabilityError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return fmt.Sprintf("runtime action %s unavailable (%s)", e.Action, e.Code)
	}
	return e.Message
}

type DefaultActionHandlerOptions struct {
	Blocklist      *Blocklist
	RemoteCaller   RemoteActionCaller
	WorkloadScaler WorkloadScaler
	RemoteTimeout  time.Duration
}

type DefaultActionHandler struct {
	blocklist      *Blocklist
	remoteCaller   RemoteActionCaller
	workloadScaler WorkloadScaler
	remoteTimeout  time.Duration
}

func NewDefaultActionHandler(opts DefaultActionHandlerOptions) *DefaultActionHandler {
	timeout := opts.RemoteTimeout
	if timeout <= 0 {
		timeout = defaultRuntimeRemoteActionTimeout
	}
	scaler := opts.WorkloadScaler
	if scaler == nil {
		scaler = NewKubernetesWorkloadScaler("", "")
	}
	return &DefaultActionHandler{
		blocklist:      opts.Blocklist,
		remoteCaller:   opts.RemoteCaller,
		workloadScaler: scaler,
		remoteTimeout:  timeout,
	}
}

func (h *DefaultActionHandler) KillProcess(ctx context.Context, resourceID string, pid int) error {
	return h.callRemoteRequired(ctx, ActionKillProcess, runtimeToolKillProcess, map[string]any{
		"resource_id": resourceID,
		"pid":         pid,
	})
}

func (h *DefaultActionHandler) IsolateContainer(ctx context.Context, containerID, namespace string) error {
	return h.callRemoteRequired(ctx, ActionIsolateContainer, runtimeToolIsolateContainer, map[string]any{
		"container_id": containerID,
		"namespace":    namespace,
	})
}

func (h *DefaultActionHandler) IsolateHost(ctx context.Context, instanceID, provider string) error {
	return h.callRemoteRequired(ctx, ActionIsolateHost, runtimeToolIsolateHost, map[string]any{
		"resource_id": instanceID,
		"provider":    provider,
	})
}

func (h *DefaultActionHandler) QuarantineFile(ctx context.Context, resourceID, path string) error {
	return h.callRemoteRequired(ctx, ActionQuarantineFile, runtimeToolQuarantineFile, map[string]any{
		"resource_id": resourceID,
		"path":        path,
	})
}

func (h *DefaultActionHandler) BlockIP(ctx context.Context, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip is required")
	}
	if h.blocklist != nil {
		h.blocklist.AddIP(ip, "runtime response containment", runtimeSourceSystem, runtimeSourceActor, nil)
	}
	_ = h.callRemoteBestEffort(ctx, runtimeToolBlockIP, map[string]any{"ip": ip})
	return nil
}

func (h *DefaultActionHandler) BlockDomain(ctx context.Context, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if h.blocklist != nil {
		h.blocklist.AddDomain(domain, "runtime response containment", runtimeSourceSystem, runtimeSourceActor, nil)
	}
	_ = h.callRemoteBestEffort(ctx, runtimeToolBlockDomain, map[string]any{"domain": domain})
	return nil
}

func (h *DefaultActionHandler) RevokeCredentials(ctx context.Context, principalID, provider string) error {
	return h.callRemoteRequired(ctx, ActionRevokeCredentials, runtimeToolRevokeCredentials, map[string]any{
		"principal_id": principalID,
		"provider":     provider,
	})
}

func (h *DefaultActionHandler) ScaleDown(ctx context.Context, resourceID string, replicas int) error {
	resourceID = strings.TrimSpace(resourceID)
	if replicas < 0 {
		return fmt.Errorf("replicas must be non-negative")
	}
	target, err := ParseWorkloadTarget(resourceID)
	if err == nil && h.workloadScaler != nil {
		if scaleErr := h.workloadScaler.ScaleDown(ctx, target, replicas); scaleErr == nil {
			return nil
		} else {
			err = scaleErr
		}
	}
	if remoteErr := h.callRemoteBestEffort(ctx, runtimeToolScaleDown, map[string]any{
		"resource_id": resourceID,
		"replicas":    replicas,
	}); remoteErr == nil {
		return nil
	}
	if err != nil {
		return err
	}
	return &ActionCapabilityError{
		Action:  ActionScaleDown,
		Code:    "direct_target_unresolved",
		Message: fmt.Sprintf("runtime action %s requires an explicit workload target", ActionScaleDown),
	}
}

func (h *DefaultActionHandler) callRemoteRequired(ctx context.Context, action ResponseActionType, tool string, payload map[string]any) error {
	if h == nil || h.remoteCaller == nil {
		return &ActionCapabilityError{
			Action:  action,
			Code:    "requires_ensemble",
			Message: fmt.Sprintf("runtime action %s requires an Ensemble remote tool", action),
		}
	}
	args, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal runtime remote payload: %w", err)
	}
	_, err = h.remoteCaller.CallTool(ctx, tool, args, remainingRuntimeTimeout(ctx, h.remoteTimeout))
	return err
}

func (h *DefaultActionHandler) callRemoteBestEffort(ctx context.Context, tool string, payload map[string]any) error {
	if h == nil || h.remoteCaller == nil {
		return fmt.Errorf("remote tool caller not configured")
	}
	args, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = h.remoteCaller.CallTool(ctx, tool, args, remainingRuntimeTimeout(ctx, h.remoteTimeout))
	return err
}

func remainingRuntimeTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = defaultRuntimeRemoteActionTimeout
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Millisecond
	}
	if remaining < fallback {
		return remaining
	}
	return fallback
}

func ParseWorkloadTarget(resourceID string) (WorkloadTarget, error) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return WorkloadTarget{}, fmt.Errorf("workload target is required")
	}
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return WorkloadTarget{}, fmt.Errorf("unsupported workload target %q", resourceID)
	}
	kind := normalizeWorkloadKind(parts[0])
	location := strings.TrimSpace(parts[1])
	locationParts := strings.SplitN(location, "/", 2)
	if kind == "" || len(locationParts) != 2 {
		return WorkloadTarget{}, fmt.Errorf("unsupported workload target %q", resourceID)
	}
	namespace := strings.TrimSpace(locationParts[0])
	name := strings.TrimSpace(locationParts[1])
	if namespace == "" || name == "" {
		return WorkloadTarget{}, fmt.Errorf("unsupported workload target %q", resourceID)
	}
	return WorkloadTarget{
		Kind:      kind,
		Namespace: namespace,
		Name:      name,
	}, nil
}

func normalizeWorkloadKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "deployment", "deploy":
		return "deployment"
	case "statefulset", "sts":
		return "statefulset"
	default:
		return ""
	}
}

type KubernetesWorkloadScaler struct {
	kubeconfig  string
	kubeContext string
}

func NewKubernetesWorkloadScaler(kubeconfig, kubeContext string) *KubernetesWorkloadScaler {
	return &KubernetesWorkloadScaler{
		kubeconfig:  strings.TrimSpace(kubeconfig),
		kubeContext: strings.TrimSpace(kubeContext),
	}
}

func (s *KubernetesWorkloadScaler) ScaleDown(ctx context.Context, target WorkloadTarget, replicas int) error {
	config, err := s.loadConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}
	switch target.Kind {
	case "deployment":
		scale, getErr := client.AppsV1().Deployments(target.Namespace).GetScale(ctx, target.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get deployment scale: %w", getErr)
		}
		scale.Spec.Replicas = int32(replicas)
		_, updateErr := client.AppsV1().Deployments(target.Namespace).UpdateScale(ctx, target.Name, scale, metav1.UpdateOptions{})
		return updateErr
	case "statefulset":
		scale, getErr := client.AppsV1().StatefulSets(target.Namespace).GetScale(ctx, target.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get statefulset scale: %w", getErr)
		}
		scale.Spec.Replicas = int32(replicas)
		_, updateErr := client.AppsV1().StatefulSets(target.Namespace).UpdateScale(ctx, target.Name, scale, metav1.UpdateOptions{})
		return updateErr
	default:
		return fmt.Errorf("unsupported workload kind %q", target.Kind)
	}
}

func (s *KubernetesWorkloadScaler) loadConfig() (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if s.kubeconfig != "" {
		rules.ExplicitPath = s.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if s.kubeContext != "" {
		overrides.CurrentContext = s.kubeContext
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := clientConfig.ClientConfig()
	if err == nil {
		return cfg, nil
	}
	if s.kubeconfig != "" {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	inClusterCfg, inClusterErr := rest.InClusterConfig()
	if inClusterErr != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return inClusterCfg, nil
}

func runtimeScaleDownTargetFromFinding(finding *RuntimeFinding) string {
	if finding == nil {
		return ""
	}
	metadata := map[string]any(nil)
	if finding.Event != nil {
		metadata = finding.Event.Metadata
	}
	kind := firstNonEmptyRuntime(
		runtimeMapValueToString(metadata, "workload_kind"),
		runtimeMapValueToString(metadata, "controller_kind"),
		finding.ResourceType,
	)
	name := firstNonEmptyRuntime(
		runtimeMapValueToString(metadata, "workload_name"),
		runtimeMapValueToString(metadata, "controller_name"),
		runtimeMapValueToString(metadata, "deployment"),
		runtimeMapValueToString(metadata, "statefulset"),
	)
	namespace := firstNonEmptyRuntime(
		runtimeMapValueToString(metadata, "namespace"),
		runtimeMapValueToString(metadata, "kubernetes_namespace"),
	)
	if finding.Event != nil && finding.Event.Container != nil {
		namespace = firstNonEmptyRuntime(namespace, finding.Event.Container.Namespace)
	}
	if name == "" {
		switch normalizeWorkloadKind(finding.ResourceType) {
		case "deployment", "statefulset":
			name = extractRuntimeResourceName(finding.ResourceID)
		}
	}
	kind = normalizeWorkloadKind(kind)
	if kind == "" || name == "" || namespace == "" {
		return ""
	}
	return WorkloadTarget{Kind: kind, Namespace: namespace, Name: name}.String()
}

func runtimeScaleDownReplicas(action PolicyAction) int {
	replicas := 0
	if action.Parameters == nil {
		return replicas
	}
	value := strings.TrimSpace(action.Parameters["replicas"])
	if value == "" {
		return replicas
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return replicas
	}
	return parsed
}

func runtimeProviderFromFinding(finding *RuntimeFinding) string {
	if finding == nil || finding.Event == nil {
		return ""
	}
	return firstNonEmptyRuntime(
		runtimeMapValueToString(finding.Event.Metadata, "provider"),
		runtimeMapValueToString(finding.Event.Metadata, "cloud_provider"),
		runtimeMapValueToString(finding.Event.Metadata, "identity_provider"),
	)
}

func runtimePrincipalIDFromFinding(finding *RuntimeFinding) string {
	if finding == nil || finding.Event == nil {
		return ""
	}
	return firstNonEmptyRuntime(
		runtimeMapValueToString(finding.Event.Metadata, "principal_id"),
		runtimeMapValueToString(finding.Event.Metadata, "credential_id"),
		runtimeMapValueToString(finding.Event.Metadata, "access_key_id"),
	)
}

func extractRuntimeResourceName(resourceID string) string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return ""
	}
	if idx := strings.LastIndex(resourceID, "/"); idx >= 0 && idx+1 < len(resourceID) {
		return strings.TrimSpace(resourceID[idx+1:])
	}
	return resourceID
}
