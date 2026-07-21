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

// Package signer implements the Check and Sign functions required by
// cert-manager/issuer-lib's CombinedController.
//
// How cert-manager external issuers work (simplified):
//
//  1. A user creates a DigiCertIssuer or DigiCertClusterIssuer resource.
//  2. issuer-lib calls Check() to verify the issuer is reachable and healthy.
//     The issuer's Ready condition is updated based on the result.
//  3. When a user creates a cert-manager CertificateRequest that references this
//     issuer, issuer-lib calls Sign() to obtain the signed certificate.
//  4. Sign() calls the DigiCert CA service and writes the resulting PEMBundle
//     back to the CertificateRequest status so cert-manager can deliver it.
//
// This package has no reconcile loop of its own; all watch/retry/status-update
// logic is handled by issuer-lib's CombinedController (wired in cmd/main.go).
package signer

import (
	"context"
	"fmt"
	"sync"

	issuerv1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiv1alpha1 "digicert-issuer/api/v1alpha1"
	"digicert-issuer/internal/caclient"
)

const (
	// AnnotationCertificateID is set on a CertificateRequest after signing to
	// record the UUID assigned by the DigiCert certificate-authority service.
	AnnotationCertificateID = "issuer.digicert.com/certificate-id"
	// AnnotationSerialNumber is set on the owning Certificate after signing to
	// record the serial number returned by the certificate-authority service.
	AnnotationSerialNumber = "issuer.digicert.com/serial-number"
)

// +kubebuilder:rbac:groups=issuer.digicert.com,resources=digicertissuers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=issuer.digicert.com,resources=digicertissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=issuer.digicert.com,resources=digicertclusterissuers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=issuer.digicert.com,resources=digicertclusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// DigiCertSigner implements the issuer-lib Check and Sign functions.
// It connects to the DigiCert certificate-authority service to validate
// issuer readiness and sign CertificateRequests.
type DigiCertSigner struct {
	// Client is the controller-runtime client used to update resources.
	Client client.Client
	// APIReader reads Secrets directly from the API server without creating
	// informer watches.
	APIReader client.Reader
	// ClusterResourceNamespace is the namespace used to resolve Secrets for
	// DigiCertClusterIssuer resources (default: "cert-manager").
	ClusterResourceNamespace string
	issuanceOutcomes         sync.Map
}

type issuanceOutcome struct {
	certificateID string
	serialNumber  string
}

// Check verifies that the certificate-authority service is reachable and that
// the configured credentials are valid. Called by the issuer reconcile loop.
func (s *DigiCertSigner) Check(ctx context.Context, issuerObj issuerv1alpha1.Issuer) error {
	spec, err := issuerSpecFrom(issuerObj)
	if err != nil {
		return err
	}

	secretNamespace := s.secretNamespace(issuerObj)
	ca, err := s.buildClient(ctx, spec, secretNamespace)
	if err != nil {
		return err
	}

	return ca.CheckIssuer(ctx, spec.IssuerID)
}

// Sign issues a certificate for the given CertificateRequest using the
// DigiCert certificate-authority service. Called by the CertificateRequest
// reconcile loop when a CertificateRequest references this issuer type.
func (s *DigiCertSigner) Sign(
	ctx context.Context,
	cr signer.CertificateRequestObject,
	issuerObj issuerv1alpha1.Issuer,
) (signer.PEMBundle, error) {
	spec, err := issuerSpecFrom(issuerObj)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	secretNamespace := s.secretNamespace(issuerObj)
	ca, err := s.buildClient(ctx, spec, secretNamespace)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	details, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("get certificate details: %w", err)
	}
	leafPEM, chainPEM, certID, serialNumber, err := ca.IssueCertificate(ctx, details.CSR, spec.IssuerID, spec.AccountID, spec.TemplateID)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("sign certificate: %w", err)
	}

	// issuer-lib writes the CertificateRequest Ready condition after Sign
	// returns. Deferring metadata updates until then prevents this callback from
	// re-enqueuing an unready request and issuing a second certificate.
	s.issuanceOutcomes.Store(cr.GetUID(), issuanceOutcome{
		certificateID: certID,
		serialNumber:  serialNumber,
	})

	return signer.PEMBundle{
		ChainPEM: chainPEM,
		CAPEM:    leafPEM,
	}, nil
}

// issuerSpecFrom extracts the IssuerSpec from either a DigiCertIssuer or
// DigiCertClusterIssuer. Returns an error for unknown issuer types.
func issuerSpecFrom(issuerObj issuerv1alpha1.Issuer) (*apiv1alpha1.IssuerSpec, error) {
	switch v := issuerObj.(type) {
	case *apiv1alpha1.DigiCertIssuer:
		return &v.Spec, nil
	case *apiv1alpha1.DigiCertClusterIssuer:
		return &v.Spec, nil
	default:
		return nil, fmt.Errorf("unknown issuer type %T", issuerObj)
	}
}

// secretNamespace returns the namespace to use when resolving the auth Secret.
// For namespaced issuers, this is the issuer's own namespace.
// For cluster-scoped issuers, this is the ClusterResourceNamespace.
func (s *DigiCertSigner) secretNamespace(issuerObj issuerv1alpha1.Issuer) string {
	switch issuerObj.(type) {
	case *apiv1alpha1.DigiCertIssuer:
		return issuerObj.GetNamespace()
	default:
		return s.ClusterResourceNamespace
	}
}

// buildClient constructs a caclient.Client by resolving the auth secret and,
// optionally, the CA bundle secret from the IssuerSpec.
func (s *DigiCertSigner) buildClient(
	ctx context.Context,
	spec *apiv1alpha1.IssuerSpec,
	namespace string,
) (*caclient.Client, error) {
	auth, err := s.buildAuthProvider(ctx, spec, namespace)
	if err != nil {
		return nil, err
	}

	var caBundlePEM []byte
	if spec.CABundleSecretName != "" {
		secret := &corev1.Secret{}
		if err := s.APIReader.Get(ctx, types.NamespacedName{
			Namespace: namespace,
			Name:      spec.CABundleSecretName,
		}, secret); err != nil {
			return nil, fmt.Errorf("get CA bundle secret %q in namespace %q: %w", spec.CABundleSecretName, namespace, err)
		}
		caBundlePEM = secret.Data["ca.crt"]
		if len(caBundlePEM) == 0 {
			return nil, fmt.Errorf("CA bundle secret %q missing key \"ca.crt\"", spec.CABundleSecretName)
		}
	}

	return caclient.New(spec.URL, auth, caBundlePEM)
}

// buildAuthProvider reads the auth Secret and returns the appropriate
// AuthProvider based on the AuthMode in the IssuerSpec.
func (s *DigiCertSigner) buildAuthProvider(
	ctx context.Context,
	spec *apiv1alpha1.IssuerSpec,
	namespace string,
) (caclient.AuthProvider, error) {
	secret := &corev1.Secret{}
	if err := s.APIReader.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      spec.AuthSecretName,
	}, secret); err != nil {
		return nil, fmt.Errorf("get auth secret %q in namespace %q: %w", spec.AuthSecretName, namespace, err)
	}

	switch spec.AuthMode {
	case "bearer":
		token, ok := secret.Data["token"]
		if !ok || len(token) == 0 {
			return nil, fmt.Errorf("auth secret %q missing key \"token\"", spec.AuthSecretName)
		}
		return &caclient.BearerAuth{Token: string(token)}, nil

	default: // apiKey
		apiKey, ok := secret.Data["api-key"]
		if !ok || len(apiKey) == 0 {
			return nil, fmt.Errorf("auth secret %q missing key \"api-key\"", spec.AuthSecretName)
		}
		return &caclient.APIKeyAuth{APIKey: string(apiKey)}, nil
	}
}
