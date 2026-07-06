// Package v1alpha1 contains the SSOConfigDrift Custom Resource Definition
// types. These are hand-written (no controller-gen in this environment) but
// follow the exact mechanical shape controller-gen would produce, including
// the DeepCopy methods, so `+kubebuilder` markers stay meaningful if
// controller-gen is wired in later.
package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// DefaultPollInterval is used when Spec.PollInterval is empty or fails to
// parse as a Go duration — this feature is report-only observability, so an
// operator typo in the poll interval degrades to "poll every 5 minutes"
// rather than a rejected CR or a stuck reconcile loop (AGENTS.md fail-open
// doctrine for observability features, mirrored from
// platform/configaudit/drift.go's own design).
const DefaultPollInterval = "5m"

// ClusterEndpoint identifies one SSO cluster's admin API: where to reach it,
// and where to find the bearer token that authenticates to it. The token
// itself is NEVER inlined in the spec — only a reference to a Secret key —
// so the CR (and any `kubectl get -o yaml`/GitOps diff of it) never carries
// a credential.
type ClusterEndpoint struct {
	// BaseURL is the scheme+host (no trailing slash) of this cluster's
	// admin API, e.g. "https://sso-a.internal:8443". MUST be https:// —
	// the controller's validateBaseURL rejects any other scheme before a
	// bearer token is ever attached to a request; see the package doc.go's
	// "Trust model" section for the full rationale.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https://.+`
	BaseURL string `json:"baseURL"`

	// BearerSecretRef points at the Secret key holding the admin:read
	// bearer token for this cluster. The Secret is looked up in the
	// SSOConfigDrift resource's own namespace, with NO further access
	// check — whoever can write this CR can cause ANY same-namespace
	// Secret named here to be read and sent (as this field's value) to
	// BaseURL. See the package doc.go's "Trust model" section: RBAC for
	// writing SSOConfigDrift MUST be no broader than RBAC for reading
	// Secrets in the same namespace.
	// +kubebuilder:validation:Required
	BearerSecretRef corev1.SecretKeySelector `json:"bearerSecretRef"`
}

// SSOConfigDriftSpec declares the two clusters to compare and how often.
type SSOConfigDriftSpec struct {
	// ClusterA is the SOURCE cluster: its running config is fetched via
	// GET /api/v1/admin/config/running.
	// +kubebuilder:validation:Required
	ClusterA ClusterEndpoint `json:"clusterA"`

	// ClusterB is the REFERENCE cluster: ClusterA's snapshot is POSTed to
	// its /api/v1/admin/config/cluster-diff, so the reported patch is
	// "what would need to change on B to match A".
	// +kubebuilder:validation:Required
	ClusterB ClusterEndpoint `json:"clusterB"`

	// PollInterval is a Go duration string (e.g. "5m", "30s"). Empty or
	// unparseable falls back to DefaultPollInterval — see its doc comment.
	// +optional
	PollInterval string `json:"pollInterval,omitempty"`
}

// SSOConfigDriftStatus reports the outcome of the most recent reconcile.
// This is the ENTIRE surface of this feature: nothing here ever triggers a
// write against either cluster (see doc.go for the explicit non-goals).
type SSOConfigDriftStatus struct {
	// LastCheckedAt is when the last fetch+diff attempt completed
	// (successfully or not).
	// +optional
	LastCheckedAt metav1.Time `json:"lastCheckedAt,omitempty"`

	// DriftDetected is true iff the last successful diff produced a
	// non-empty RFC 6902 patch. Stays at its previous value across a
	// failed attempt (a transient HTTP error is not "no drift").
	// +optional
	DriftDetected bool `json:"driftDetected,omitempty"`

	// PatchOpCount is len(patch) from the last successful diff.
	// +optional
	PatchOpCount int `json:"patchOpCount,omitempty"`

	// Message is a short human-readable summary: either a drift/no-drift
	// summary or the last error's text. NEVER contains a bearer token —
	// see doc.go's "never log/persist tokens" invariant.
	// +optional
	Message string `json:"message,omitempty"`

	// ObservedGeneration lets a client tell whether Status reflects the
	// most recently applied Spec (standard controller-runtime idiom).
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// SSOConfigDrift is the Schema for the ssoconfigdrifts API — a declarative,
// read-only request to compare two SSO clusters' running config and report
// (never apply) the resulting drift.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Drift",type=boolean,JSONPath=`.status.driftDetected`
// +kubebuilder:printcolumn:name="Ops",type=integer,JSONPath=`.status.patchOpCount`
// +kubebuilder:printcolumn:name="LastChecked",type=date,JSONPath=`.status.lastCheckedAt`
type SSOConfigDrift struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SSOConfigDriftSpec   `json:"spec,omitempty"`
	Status SSOConfigDriftStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SSOConfigDriftList contains a list of SSOConfigDrift.
type SSOConfigDriftList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SSOConfigDrift `json:"items"`
}

// GroupVersion is the API group+version this package registers into a
// runtime.Scheme.
var GroupVersion = schema.GroupVersion{Group: "sso.snaplink.io", Version: "v1alpha1"}

// SchemeBuilder collects the AddToScheme funcs for this package, mirroring
// the standard kubebuilder-scaffolded groupversion_info.go pattern.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds this package's types to the given scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &SSOConfigDrift{}, &SSOConfigDriftList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}

// DeepCopyInto is a hand-written mechanical deep copy, following the exact
// shape controller-gen's zz_generated.deepcopy.go would emit (no codegen
// tool available in this environment — see doc.go).
func (in *ClusterEndpoint) DeepCopyInto(out *ClusterEndpoint) {
	*out = *in
	out.BearerSecretRef = in.BearerSecretRef
}

// DeepCopy returns a deep copy of ClusterEndpoint.
func (in *ClusterEndpoint) DeepCopy() *ClusterEndpoint {
	if in == nil {
		return nil
	}
	out := new(ClusterEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies every field of SSOConfigDriftSpec.
func (in *SSOConfigDriftSpec) DeepCopyInto(out *SSOConfigDriftSpec) {
	*out = *in
	in.ClusterA.DeepCopyInto(&out.ClusterA)
	in.ClusterB.DeepCopyInto(&out.ClusterB)
}

// DeepCopy returns a deep copy of SSOConfigDriftSpec.
func (in *SSOConfigDriftSpec) DeepCopy() *SSOConfigDriftSpec {
	if in == nil {
		return nil
	}
	out := new(SSOConfigDriftSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies every field of SSOConfigDriftStatus.
func (in *SSOConfigDriftStatus) DeepCopyInto(out *SSOConfigDriftStatus) {
	*out = *in
	in.LastCheckedAt.DeepCopyInto(&out.LastCheckedAt)
}

// DeepCopy returns a deep copy of SSOConfigDriftStatus.
func (in *SSOConfigDriftStatus) DeepCopy() *SSOConfigDriftStatus {
	if in == nil {
		return nil
	}
	out := new(SSOConfigDriftStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies every field of SSOConfigDrift, including the embedded
// ObjectMeta (via its own generated DeepCopyInto).
func (in *SSOConfigDrift) DeepCopyInto(out *SSOConfigDrift) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of SSOConfigDrift.
func (in *SSOConfigDrift) DeepCopy() *SSOConfigDrift {
	if in == nil {
		return nil
	}
	out := new(SSOConfigDrift)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object — required for a type to be
// registered in a scheme and handled generically by controller-runtime's
// client.
func (in *SSOConfigDrift) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies every field of SSOConfigDriftList, including each
// Item via SSOConfigDrift's own DeepCopyInto.
func (in *SSOConfigDriftList) DeepCopyInto(out *SSOConfigDriftList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]SSOConfigDrift, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

// DeepCopy returns a deep copy of SSOConfigDriftList.
func (in *SSOConfigDriftList) DeepCopy() *SSOConfigDriftList {
	if in == nil {
		return nil
	}
	out := new(SSOConfigDriftList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object for SSOConfigDriftList.
func (in *SSOConfigDriftList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
