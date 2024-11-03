package kubernetes

// Update other structs similarly if needed
// For example, update Pod, Namespace, DaemonSet structs

// Pod represents a Kubernetes Pod object
type Pod struct {
	Kind       string                 `json:"kind"`
	APIVersion string                 `json:"apiVersion"`
	Metadata   map[string]interface{} `json:"metadata"`
	Spec       map[string]interface{} `json:"spec"`
}

// Namespace represents a Kubernetes Namespace object
type Namespace struct {
	Kind       string                 `json:"kind"`
	APIVersion string                 `json:"apiVersion"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DaemonSet represents a Kubernetes DaemonSet object
type DaemonSet struct {
	Kind       string                 `json:"kind"`
	APIVersion string                 `json:"apiVersion"`
	Metadata   map[string]interface{} `json:"metadata"`
	Spec       map[string]interface{} `json:"spec"`
}

type ObjectMeta struct {
	Name            string            `json:"name,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	OwnerReferences []OwnerReference  `json:"ownerReferences,omitempty"`
}

// OwnerReference represents an owner reference to another Kubernetes object
type OwnerReference struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	UID        string `json:"uid,omitempty"`
}

// Deployment represents a Kubernetes Deployment object
type Deployment struct {
	Kind       string           `json:"kind,omitempty"`
	APIVersion string           `json:"apiVersion,omitempty"`
	Metadata   ObjectMeta       `json:"metadata,omitempty"`
	Spec       DeploymentSpec   `json:"spec,omitempty"`
	Status     DeploymentStatus `json:"status,omitempty"`
}

// DeploymentSpec represents the spec of a Deployment
type DeploymentSpec struct {
	Replicas int32              `json:"replicas,omitempty"`
	Selector LabelSelector      `json:"selector,omitempty"`
	Template PodTemplateSpec    `json:"template,omitempty"`
	Strategy DeploymentStrategy `json:"strategy,omitempty"`
}

// LabelSelector represents a label query over a set of resources
type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// PodTemplateSpec describes the data a pod should have when created from a template
type PodTemplateSpec struct {
	Metadata ObjectMeta `json:"metadata,omitempty"`
	Spec     PodSpec    `json:"spec,omitempty"`
}

// PodSpec is a description of a pod
type PodSpec struct {
	Containers []Container `json:"containers"`
}

// Container represents a single container
type Container struct {
	Name  string `json:"name,omitempty"`
	Image string `json:"image,omitempty"`
	// Add other container fields as needed
}

// DeploymentStrategy describes how to replace existing pods with new ones
type DeploymentStrategy struct {
	Type string `json:"type,omitempty"`
	// Add other strategy fields as needed
}

// DeploymentStatus represents the current status of a deployment
type DeploymentStatus struct {
	Replicas int32 `json:"replicas,omitempty"`
	// Add other status fields as needed
}
