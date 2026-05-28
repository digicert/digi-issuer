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

package signer

import (
	"context"
	"fmt"

	issuerv1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiv1alpha1 "digicert-issuer/api/v1alpha1"
	"digicert-issuer/internal/caclient"
)

// DigiCertSigner implements the issuer-lib Check and Sign functions.
// It connects to the DigiCert certificate-authority service to validate
// issuer readiness and sign CertificateRequests.
type DigiCertSigner struct {
	// Client is the controller-runtime client used to read Kubernetes Secrets.
	Client client.Client
	// ClusterResourceNamespace is the namespace used to resolve Secrets for
	// DigiCertClusterIssuer resources (default: "cert-manager").
	ClusterResourceNamespace string
}

// Check verifies that the certificate-authority service is reachable and that
// the configured credentials are valid. Called by the issuer reconcile loop.
func (s *DigiCertSigner) Check(ctx context.Context, issuerObj issuerv1alpha1.Issuer) error {
	spec, err := issuerSpecFrom(issuerObj)
	if err != nil {
		return err
	}

	secretNamespace := s.secretNamespace(issuerObj)
	auth, err := s.buildAuthProvider(ctx, spec, secretNamespace)
	if err != nil {
		return err
	}

	ca := caclient.New(spec.URL, auth)
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
	auth, err := s.buildAuthProvider(ctx, spec, secretNamespace)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	ca := caclient.New(spec.URL, auth)

	details, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("get certificate details: %w", err)
	}
	leafPEM, chainPEM, err := ca.IssueCertificate(ctx, details.CSR, spec.IssuerID, spec.TemplateID)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("sign certificate: %w", err)
	}

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

// buildAuthProvider reads the auth Secret and returns the appropriate
// AuthProvider based on the AuthMode in the IssuerSpec.
func (s *DigiCertSigner) buildAuthProvider(
	ctx context.Context,
	spec *apiv1alpha1.IssuerSpec,
	namespace string,
) (caclient.AuthProvider, error) {
	secret := &corev1.Secret{}
	if err := s.Client.Get(ctx, types.NamespacedName{
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

	default: // standalone
		apiKey, ok := secret.Data["api-key"]
		if !ok || len(apiKey) == 0 {
			return nil, fmt.Errorf("auth secret %q missing key \"api-key\"", spec.AuthSecretName)
		}
		return &caclient.StandaloneAuth{APIKey: string(apiKey)}, nil
	}
}
