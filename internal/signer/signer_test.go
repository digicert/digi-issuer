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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerlibsigner "github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	apiv1alpha1 "digicert-issuer/api/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := cmapi.AddToScheme(scheme); err != nil {
		t.Fatalf("add cert-manager scheme: %v", err)
	}
	if err := apiv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add apiv1alpha1 scheme: %v", err)
	}
	return scheme
}

// generateCSRPEM creates a properly self-signed (valid CheckSignature) PEM
// encoded PKCS#10 CSR for use in Sign() tests.
func generateCSRPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// generateSelfSignedCertDER creates a self-signed leaf certificate and
// returns its DER bytes, for use as a fake CA response blob.
func generateSelfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func TestIssuerSpecFrom(t *testing.T) {
	namespacedIssuer := &apiv1alpha1.DigiCertIssuer{Spec: apiv1alpha1.IssuerSpec{URL: "https://namespaced"}}
	clusterIssuer := &apiv1alpha1.DigiCertClusterIssuer{Spec: apiv1alpha1.IssuerSpec{URL: "https://cluster"}}

	spec, err := issuerSpecFrom(namespacedIssuer)
	if err != nil || spec.URL != "https://namespaced" {
		t.Fatalf("issuerSpecFrom(namespaced) = %+v, %v", spec, err)
	}

	spec, err = issuerSpecFrom(clusterIssuer)
	if err != nil || spec.URL != "https://cluster" {
		t.Fatalf("issuerSpecFrom(cluster) = %+v, %v", spec, err)
	}

	if _, err := issuerSpecFrom(nil); err == nil {
		t.Fatal("issuerSpecFrom(nil) expected an error for unknown issuer type")
	}
}

func TestSecretNamespace(t *testing.T) {
	s := &DigiCertSigner{ClusterResourceNamespace: "cert-manager"}

	namespacedIssuer := &apiv1alpha1.DigiCertIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"},
	}
	if got := s.secretNamespace(namespacedIssuer); got != "team-a" {
		t.Errorf("secretNamespace(namespaced issuer) = %q, want %q", got, "team-a")
	}

	clusterIssuer := &apiv1alpha1.DigiCertClusterIssuer{}
	if got := s.secretNamespace(clusterIssuer); got != "cert-manager" {
		t.Errorf("secretNamespace(cluster issuer) = %q, want %q", got, "cert-manager")
	}
}

func TestBuildAuthProvider(t *testing.T) {
	tests := []struct {
		name       string
		authMode   string
		secretData map[string][]byte
		noSecret   bool
		wantErr    string
		wantHeader string
		wantValue  string
	}{
		{
			name:       "bearer success",
			authMode:   "bearer",
			secretData: map[string][]byte{"token": []byte("t0ken")},
			wantHeader: "Authorization",
			wantValue:  "Bearer t0ken",
		},
		{
			name:       "bearer missing token key",
			authMode:   "bearer",
			secretData: map[string][]byte{"other": []byte("x")},
			wantErr:    `missing key "token"`,
		},
		{
			name:       "apiKey success",
			authMode:   "apiKey",
			secretData: map[string][]byte{"api-key": []byte("k3y")},
			wantHeader: "x-api-key",
			wantValue:  "k3y",
		},
		{
			name:       "apiKey missing api-key",
			authMode:   "apiKey",
			secretData: map[string][]byte{"other": []byte("x")},
			wantErr:    `missing key "api-key"`,
		},
		{
			name:     "unknown auth mode fails closed",
			authMode: "mTLS",
			wantErr:  `unsupported auth mode "mTLS"`,
		},
		{
			name:     "missing secret",
			authMode: "apiKey",
			noSecret: true,
			wantErr:  "get auth secret",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := testScheme(t)
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if !test.noSecret {
				builder = builder.WithObjects(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns1"},
					Data:       test.secretData,
				})
			}
			fakeClient := builder.Build()
			s := &DigiCertSigner{APIReader: fakeClient}

			auth, err := s.buildAuthProvider(context.Background(), &apiv1alpha1.IssuerSpec{
				AuthSecretName: "creds",
				AuthMode:       test.authMode,
			}, "ns1")

			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("buildAuthProvider() error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildAuthProvider() unexpected error = %v", err)
			}
			name, value, err := auth.Header()
			if err != nil {
				t.Fatalf("auth.Header() error = %v", err)
			}
			if name != test.wantHeader || value != test.wantValue {
				t.Errorf("auth.Header() = (%q, %q), want (%q, %q)", name, value, test.wantHeader, test.wantValue)
			}
		})
	}
}

func TestCertificateOwnerReference(t *testing.T) {
	owners := []metav1.OwnerReference{
		{APIVersion: "v1", Kind: "Pod", Name: "irrelevant"},
		{APIVersion: cmapi.SchemeGroupVersion.String(), Kind: "Certificate", Name: "my-cert", UID: types.UID("abc")},
	}
	owner := certificateOwnerReference(owners)
	if owner == nil || owner.Name != "my-cert" {
		t.Fatalf("certificateOwnerReference() = %+v, want owner named my-cert", owner)
	}

	if got := certificateOwnerReference(nil); got != nil {
		t.Errorf("certificateOwnerReference(nil) = %+v, want nil", got)
	}
	if got := certificateOwnerReference(owners[:1]); got != nil {
		t.Errorf("certificateOwnerReference(no Certificate owner) = %+v, want nil", got)
	}
}

func TestAnnotateIssuanceOutcome(t *testing.T) {
	t.Run("both empty is a no-op and requires no API calls", func(t *testing.T) {
		scheme := testScheme(t)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build() // no objects registered
		s := &DigiCertSigner{Client: fakeClient}

		cr := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: "cr1", Namespace: "ns1"}}
		if err := s.annotateIssuanceOutcome(context.Background(), issuerlibsigner.CertificateRequestObjectFromCertificateRequest(cr), "", ""); err != nil {
			t.Fatalf("annotateIssuanceOutcome() unexpected error = %v", err)
		}
	})

	t.Run("annotates CertificateRequest with certificate ID", func(t *testing.T) {
		scheme := testScheme(t)
		crObj := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: "cr1", Namespace: "ns1"}}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crObj).Build()
		s := &DigiCertSigner{Client: fakeClient}

		err := s.annotateIssuanceOutcome(context.Background(),
			issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), "cert-id-123", "")
		if err != nil {
			t.Fatalf("annotateIssuanceOutcome() unexpected error = %v", err)
		}

		got := &cmapi.CertificateRequest{}
		if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "cr1", Namespace: "ns1"}, got); err != nil {
			t.Fatalf("get CertificateRequest: %v", err)
		}
		if got.Annotations[AnnotationCertificateID] != "cert-id-123" {
			t.Errorf("CertificateRequest annotation %q = %q, want %q",
				AnnotationCertificateID, got.Annotations[AnnotationCertificateID], "cert-id-123")
		}
	})

	t.Run("skips serial-number annotation when there is no owning Certificate", func(t *testing.T) {
		scheme := testScheme(t)
		crObj := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: "cr1", Namespace: "ns1"}}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crObj).Build()
		s := &DigiCertSigner{Client: fakeClient}

		if err := s.annotateIssuanceOutcome(context.Background(),
			issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), "", "serial-456"); err != nil {
			t.Fatalf("annotateIssuanceOutcome() unexpected error = %v", err)
		}
		// No panic/error is sufficient here: there is no Certificate object to
		// assert against, and none should have been created.
	})

	t.Run("skips serial-number annotation when owner UID does not match", func(t *testing.T) {
		scheme := testScheme(t)
		cert := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cert", Namespace: "ns1", UID: types.UID("real-uid")},
		}
		crObj := &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cr1", Namespace: "ns1",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: cmapi.SchemeGroupVersion.String(), Kind: "Certificate", Name: "my-cert", UID: types.UID("stale-uid")},
				},
			},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crObj, cert).Build()
		s := &DigiCertSigner{Client: fakeClient}

		if err := s.annotateIssuanceOutcome(context.Background(),
			issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), "", "serial-789"); err != nil {
			t.Fatalf("annotateIssuanceOutcome() unexpected error = %v", err)
		}

		got := &cmapi.Certificate{}
		if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "my-cert", Namespace: "ns1"}, got); err != nil {
			t.Fatalf("get Certificate: %v", err)
		}
		if _, ok := got.Annotations[AnnotationSerialNumber]; ok {
			t.Errorf("Certificate should not have been annotated when owner UID mismatches, got annotations = %v", got.Annotations)
		}
	})

	t.Run("annotates the owning Certificate with the serial number", func(t *testing.T) {
		scheme := testScheme(t)
		cert := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cert", Namespace: "ns1", UID: types.UID("matching-uid")},
		}
		crObj := &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cr1", Namespace: "ns1",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: cmapi.SchemeGroupVersion.String(), Kind: "Certificate", Name: "my-cert", UID: types.UID("matching-uid")},
				},
			},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crObj, cert).Build()
		s := &DigiCertSigner{Client: fakeClient}

		err := s.annotateIssuanceOutcome(context.Background(),
			issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), "cert-id-999", "serial-999")
		if err != nil {
			t.Fatalf("annotateIssuanceOutcome() unexpected error = %v", err)
		}

		gotCR := &cmapi.CertificateRequest{}
		if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "cr1", Namespace: "ns1"}, gotCR); err != nil {
			t.Fatalf("get CertificateRequest: %v", err)
		}
		if gotCR.Annotations[AnnotationCertificateID] != "cert-id-999" {
			t.Errorf("CertificateRequest annotation = %q, want %q", gotCR.Annotations[AnnotationCertificateID], "cert-id-999")
		}

		gotCert := &cmapi.Certificate{}
		if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "my-cert", Namespace: "ns1"}, gotCert); err != nil {
			t.Fatalf("get Certificate: %v", err)
		}
		if gotCert.Annotations[AnnotationSerialNumber] != "serial-999" {
			t.Errorf("Certificate annotation = %q, want %q", gotCert.Annotations[AnnotationSerialNumber], "serial-999")
		}
	})
}

func TestSetAnnotationIsIdempotent(t *testing.T) {
	scheme := testScheme(t)
	crObj := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cr1", Namespace: "ns1",
			Annotations: map[string]string{"issuer.digicert.com/certificate-id": "already-set"},
		},
	}
	patchCalls := 0
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crObj).Build()
	countingClient := interceptingPatchClient{WithWatch: fakeClient, count: &patchCalls}

	if err := setAnnotation(context.Background(), countingClient, crObj, "issuer.digicert.com/certificate-id", "already-set"); err != nil {
		t.Fatalf("setAnnotation() unexpected error = %v", err)
	}
	if patchCalls != 0 {
		t.Errorf("setAnnotation() issued %d patch calls for an already-correct annotation, want 0", patchCalls)
	}

	if err := setAnnotation(context.Background(), countingClient, crObj, "issuer.digicert.com/certificate-id", "changed"); err != nil {
		t.Fatalf("setAnnotation() unexpected error = %v", err)
	}
	if patchCalls != 1 {
		t.Errorf("setAnnotation() issued %d patch calls for a changed annotation, want 1", patchCalls)
	}
}

// interceptingPatchClient wraps a client.WithWatch and counts Patch calls,
// without needing the full interceptor.Funcs machinery for this single test.
type interceptingPatchClient struct {
	client.WithWatch
	count *int
}

func (c interceptingPatchClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	*c.count++
	return c.WithWatch.Patch(ctx, obj, patch, opts...)
}

// /api/v1/health and /api/v1/certificate endpoints.
// caTestServer starts an httptest server that emulates the DigiCert CA's
// /api/v1/health and /api/v1/certificate endpoints.
func caTestServer(t *testing.T, certDER []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/certificate", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id":            "ca-cert-id",
			"blob":          base64.StdEncoding.EncodeToString(certDER),
			"serial_number": "aabbccdd",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode CA response: %v", err)
		}
	})
	return httptest.NewServer(mux)
}

func TestCheck(t *testing.T) {
	server := caTestServer(t, nil)
	defer server.Close()

	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns1"},
		Data:       map[string][]byte{"api-key": []byte("k3y")},
	}).Build()

	s := &DigiCertSigner{Client: fakeClient, APIReader: fakeClient}
	issuer := &apiv1alpha1.DigiCertIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"},
		Spec: apiv1alpha1.IssuerSpec{
			URL:            server.URL,
			AuthSecretName: "creds",
			AuthMode:       "apiKey",
			IssuerID:       "issuer-1",
		},
	}

	if err := s.Check(context.Background(), issuer); err != nil {
		t.Fatalf("Check() unexpected error = %v", err)
	}
}

func TestSignEndToEnd(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)
	server := caTestServer(t, certDER)
	defer server.Close()

	scheme := testScheme(t)
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cert", Namespace: "ns1", UID: types.UID("cert-uid")},
	}
	crObj := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cr1", Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: cmapi.SchemeGroupVersion.String(), Kind: "Certificate", Name: "my-cert", UID: types.UID("cert-uid")},
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Request: generateCSRPEM(t, "leaf.example.com"),
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crObj, cert, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns1"},
			Data:       map[string][]byte{"api-key": []byte("k3y")},
		}).
		Build()

	s := &DigiCertSigner{Client: fakeClient, APIReader: fakeClient}
	issuer := &apiv1alpha1.DigiCertIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"},
		Spec: apiv1alpha1.IssuerSpec{
			URL:            server.URL,
			AuthSecretName: "creds",
			AuthMode:       "apiKey",
			IssuerID:       "issuer-1",
			AccountID:      "account-1",
			TemplateID:     "template-1",
		},
	}

	bundle, err := s.Sign(context.Background(), issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), issuer)
	if err != nil {
		t.Fatalf("Sign() unexpected error = %v", err)
	}
	if len(bundle.CAPEM) == 0 || len(bundle.ChainPEM) == 0 {
		t.Fatalf("Sign() returned empty PEM bundle: %+v", bundle)
	}
	if !strings.Contains(string(bundle.ChainPEM), "BEGIN CERTIFICATE") {
		t.Errorf("ChainPEM does not contain a PEM certificate block: %s", bundle.ChainPEM)
	}

	// The CertificateRequest should have been annotated with the CA-assigned
	// certificate ID, durably, as part of Sign() itself.
	gotCR := &cmapi.CertificateRequest{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "cr1", Namespace: "ns1"}, gotCR); err != nil {
		t.Fatalf("get CertificateRequest: %v", err)
	}
	if gotCR.Annotations[AnnotationCertificateID] != "ca-cert-id" {
		t.Errorf("CertificateRequest annotation = %q, want %q", gotCR.Annotations[AnnotationCertificateID], "ca-cert-id")
	}

	// The owning Certificate should have been annotated with the serial number.
	gotCert := &cmapi.Certificate{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "my-cert", Namespace: "ns1"}, gotCert); err != nil {
		t.Fatalf("get Certificate: %v", err)
	}
	if gotCert.Annotations[AnnotationSerialNumber] != "aabbccdd" {
		t.Errorf("Certificate annotation = %q, want %q", gotCert.Annotations[AnnotationSerialNumber], "aabbccdd")
	}
}

func TestSignRejectsUnsignedCSR(t *testing.T) {
	// A CSR whose signature doesn't match its claimed content should be
	// rejected by caclient's CheckSignature() gate before ever reaching the
	// CA, regardless of what the CA test server would return.
	server := caTestServer(t, generateSelfSignedCertDER(t))
	defer server.Close()

	scheme := testScheme(t)
	badCSR := generateCSRPEM(t, "leaf.example.com")
	// Corrupt the DER payload inside the PEM block so the signature no longer
	// matches, without invalidating the PEM envelope itself.
	block, _ := pem.Decode(badCSR)
	block.Bytes[len(block.Bytes)-1] ^= 0xFF
	corrupted := pem.EncodeToMemory(block)

	crObj := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "cr1", Namespace: "ns1"},
		Spec:       cmapi.CertificateRequestSpec{Request: corrupted},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crObj, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns1"},
			Data:       map[string][]byte{"api-key": []byte("k3y")},
		}).
		Build()

	s := &DigiCertSigner{Client: fakeClient, APIReader: fakeClient}
	issuer := &apiv1alpha1.DigiCertIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"},
		Spec: apiv1alpha1.IssuerSpec{
			URL:            server.URL,
			AuthSecretName: "creds",
			AuthMode:       "apiKey",
			IssuerID:       "issuer-1",
			AccountID:      "account-1",
			TemplateID:     "template-1",
		},
	}

	_, err := s.Sign(context.Background(), issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), issuer)
	if err == nil {
		t.Fatal("Sign() expected an error for a CSR with an invalid signature, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("Sign() error = %v, want it to mention signature verification failure", err)
	}
}

func TestBuildClientLogsWhenNoCABundleConfigured(t *testing.T) {
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns1"},
		Data:       map[string][]byte{"api-key": []byte("k3y")},
	}).Build()

	s := &DigiCertSigner{APIReader: fakeClient}
	ca, err := s.buildClient(context.Background(), &apiv1alpha1.IssuerSpec{
		URL:            "https://example.invalid",
		AuthSecretName: "creds",
		AuthMode:       "apiKey",
	}, "ns1")
	if err != nil {
		t.Fatalf("buildClient() unexpected error = %v", err)
	}
	if ca == nil {
		t.Fatal("buildClient() returned nil client without error")
	}
}

func TestBuildClientMissingCABundleSecret(t *testing.T) {
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns1"},
		Data:       map[string][]byte{"api-key": []byte("k3y")},
	}).Build()

	s := &DigiCertSigner{APIReader: fakeClient}
	_, err := s.buildClient(context.Background(), &apiv1alpha1.IssuerSpec{
		URL:                "https://example.invalid",
		AuthSecretName:     "creds",
		AuthMode:           "apiKey",
		CABundleSecretName: "missing-bundle",
	}, "ns1")
	if err == nil || !strings.Contains(err.Error(), "get CA bundle secret") {
		t.Fatalf("buildClient() error = %v, want error about missing CA bundle secret", err)
	}
}

func TestCheckPropagatesUnknownIssuerTypeError(t *testing.T) {
	s := &DigiCertSigner{}
	if err := s.Check(context.Background(), nil); err == nil {
		t.Fatal("Check() expected an error for a nil/unknown issuer type")
	}
}

func TestSignPropagatesUnknownIssuerTypeError(t *testing.T) {
	s := &DigiCertSigner{}
	crObj := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: "cr1", Namespace: "ns1"}}
	_, err := s.Sign(context.Background(), issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), nil)
	if err == nil {
		t.Fatal("Sign() expected an error for a nil/unknown issuer type")
	}
}

func TestBuildClientPropagatesAuthProviderError(t *testing.T) {
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build() // no Secret registered
	s := &DigiCertSigner{APIReader: fakeClient}

	_, err := s.buildClient(context.Background(), &apiv1alpha1.IssuerSpec{
		URL:            "https://example.invalid",
		AuthSecretName: "missing-creds",
		AuthMode:       "apiKey",
	}, "ns1")
	if err == nil || !strings.Contains(err.Error(), "get auth secret") {
		t.Fatalf("buildClient() error = %v, want error about missing auth secret", err)
	}
}

func TestSignPropagatesCAError(t *testing.T) {
	// A server that always returns a 500 for /api/v1/certificate causes
	// IssueCertificate (and therefore Sign) to fail.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	scheme := testScheme(t)
	crObj := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "cr1", Namespace: "ns1"},
		Spec:       cmapi.CertificateRequestSpec{Request: generateCSRPEM(t, "leaf.example.com")},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crObj, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns1"},
			Data:       map[string][]byte{"api-key": []byte("k3y")},
		}).
		Build()

	s := &DigiCertSigner{Client: fakeClient, APIReader: fakeClient}
	issuer := &apiv1alpha1.DigiCertIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1"},
		Spec: apiv1alpha1.IssuerSpec{
			URL:            server.URL,
			AuthSecretName: "creds",
			AuthMode:       "apiKey",
			IssuerID:       "issuer-1",
			AccountID:      "account-1",
			TemplateID:     "template-1",
		},
	}

	_, err := s.Sign(context.Background(), issuerlibsigner.CertificateRequestObjectFromCertificateRequest(crObj), issuer)
	if err == nil || !strings.Contains(err.Error(), "sign certificate") {
		t.Fatalf("Sign() error = %v, want error wrapping the CA failure", err)
	}
}
