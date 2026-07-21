package caclient

import (
	"context"
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
