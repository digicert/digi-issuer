/*
Copyright 2026 DigiCert, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	issuerv1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// DigiCertClusterIssuer is the Schema for the digicertclusterissuers API.
// It is cluster-scoped and signs certificate requests via the DigiCert
// certificate-authority service. Secrets are resolved from the
// --cluster-resource-namespace (default: cert-manager).
type DigiCertClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec                  `json:"spec,omitempty"`
	Status issuerv1alpha1.IssuerStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions for this cluster issuer.
// Required by the issuer-lib Issuer interface.
func (i *DigiCertClusterIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}

// GetIssuerTypeIdentifier returns the unique identifier for this cluster issuer type.
// This is used by issuer-lib to match CertificateSigningRequests to this controller.
// Format: "<plural-resource>.<api-group>"
func (i *DigiCertClusterIssuer) GetIssuerTypeIdentifier() string {
	return "digicertclusterissuers.issuer.digicert.com"
}

// Ensure DigiCertClusterIssuer implements the issuer-lib Issuer interface.
var _ issuerv1alpha1.Issuer = &DigiCertClusterIssuer{}

// +kubebuilder:object:root=true

// DigiCertClusterIssuerList contains a list of DigiCertClusterIssuer.
type DigiCertClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DigiCertClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &DigiCertClusterIssuer{}, &DigiCertClusterIssuerList{})
		return nil
	})
}
