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

// IssuerSpec defines the desired state of DigiCertIssuer and DigiCertClusterIssuer.
type IssuerSpec struct {
	// URL is the base URL of the DigiCert certificate-authority service,
	// e.g. "https://certificate-authority.cert-manager.svc.cluster.local".
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// AuthSecretName is the name of a Kubernetes Secret containing credentials
	// for authenticating to the certificate-authority service.
	// For standalone mode (default), the Secret must contain the key "api-key".
	// For bearer mode, the Secret must contain the key "token".
	// +kubebuilder:validation:Required
	AuthSecretName string `json:"authSecretName"`

	// AuthMode controls which authentication method is used when calling the
	// certificate-authority service.
	// "standalone" uses the x-api-key header (default).
	// "bearer" uses an Authorization: Bearer token header.
	// +kubebuilder:validation:Enum=standalone;bearer
	// +kubebuilder:default=standalone
	// +optional
	AuthMode string `json:"authMode,omitempty"`

	// IssuerID is the UUID of the issuing CA within the certificate-authority
	// service that will sign certificate requests.
	// +kubebuilder:validation:Required
	IssuerID string `json:"issuerID"`

	// TemplateID is the optional UUID of a certificate template to apply when
	// issuing certificates. If omitted, no template is specified in the request.
	// +optional
	TemplateID string `json:"templateID,omitempty"`

	// CABundleSecretName is the optional name of a Secret containing a
	// PEM-encoded CA bundle (key: "ca.crt") used to verify TLS connections to
	// the certificate-authority service. If omitted, TLS verification is skipped.
	// +optional
	CABundleSecretName string `json:"caBundleSecretName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// DigiCertIssuer is the Schema for the digicertissuers API.
// It represents a namespaced issuer that signs certificate requests
// via the DigiCert certificate-authority service.
type DigiCertIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec                  `json:"spec,omitempty"`
	Status issuerv1alpha1.IssuerStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions for this issuer.
// Required by the issuer-lib Issuer interface.
func (i *DigiCertIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}

// GetIssuerTypeIdentifier returns the unique identifier for this issuer type.
// This is used by issuer-lib to match CertificateSigningRequests to this controller.
// Format: "<plural-resource>.<api-group>"
func (i *DigiCertIssuer) GetIssuerTypeIdentifier() string {
	return "digicertissuers.issuer.digicert.com"
}

// Ensure DigiCertIssuer implements the issuer-lib Issuer interface.
var _ issuerv1alpha1.Issuer = &DigiCertIssuer{}

// +kubebuilder:object:root=true

// DigiCertIssuerList contains a list of DigiCertIssuer.
type DigiCertIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DigiCertIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &DigiCertIssuer{}, &DigiCertIssuerList{})
		return nil
	})
}
