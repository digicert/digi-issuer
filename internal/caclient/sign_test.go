package caclient

import (
	"context"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
)

func TestIssueCertificateRequiresAccountAndTemplateIDs(t *testing.T) {
	tests := []struct {
		name       string
		accountID  string
		templateID string
		wantError  string
	}{
		{
			name:       "missing account ID",
			templateID: "template-id",
			wantError:  "accountID must not be empty",
		},
		{
			name:      "missing template ID",
			accountID: "account-id",
			wantError: "templateID must not be empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, _, err := (*Client)(nil).IssueCertificate(
				context.Background(), []byte("csr"), "issuer-id", test.accountID, test.templateID,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("IssueCertificate() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestExtensionsFromCSRIncludesEmailAndURISANs(t *testing.T) {
	uri, err := url.Parse("spiffe://example.test/workload/api")
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}

	extensions := extensionsFromCSR(&x509.CertificateRequest{
		EmailAddresses: []string{"service@example.test"},
		URIs:           []*url.URL{uri},
	})

	if extensions == nil || extensions.SAN == nil {
		t.Fatal("extensionsFromCSR() = nil, want SAN extensions")
	}
	if got := extensions.SAN.EmailAddresses; len(got) != 1 || got[0] != "service@example.test" {
		t.Errorf("email_addresses = %v, want [service@example.test]", got)
	}
	if got := extensions.SAN.URIs; len(got) != 1 || got[0] != "spiffe://example.test/workload/api" {
		t.Errorf("uris = %v, want [spiffe://example.test/workload/api]", got)
	}
}
