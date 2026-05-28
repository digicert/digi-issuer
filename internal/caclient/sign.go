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

package caclient

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// IssueCertificate sends the PEM-encoded CSR to the certificate-authority
// service and returns the signed leaf certificate and chain as PEM bundles.
//
// leafPEM contains the signed end-entity certificate.
// chainPEM contains the full issuing chain (leaf first, root last) as
// concatenated PEM blocks, suitable for use as the cert-manager PEMBundle.
func (c *Client) IssueCertificate(
	ctx context.Context,
	csrPEM []byte,
	issuerID string,
	templateID string,
) (leafPEM []byte, chainPEM []byte, err error) {
	if len(csrPEM) == 0 {
		return nil, nil, fmt.Errorf("CSR must not be empty")
	}
	if issuerID == "" {
		return nil, nil, fmt.Errorf("issuerID must not be empty")
	}

	reqBody := certificateRequest{
		CSR:        string(csrPEM),
		Issuer:     certIssuer{ID: issuerID},
		TemplateID: templateID,
	}

	var resp certificateResponse
	if err := c.do(ctx, "POST", "/certificate-authority/api/v1/certificate", reqBody, &resp); err != nil {
		return nil, nil, fmt.Errorf("issue certificate: %w", err)
	}

	// The leaf blob comes back as raw bytes (already decoded from JSON []byte).
	if len(resp.Blob) == 0 {
		return nil, nil, fmt.Errorf("issue certificate: response contained empty blob")
	}

	leafPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: resp.Blob,
	})

	// Assemble the full chain: leaf first, then any CA chain certificates.
	chainPEM = append(chainPEM, leafPEM...)
	for _, chainCert := range resp.Chain {
		if chainCert.Blob == "" {
			continue
		}
		derBytes, err := base64.StdEncoding.DecodeString(chainCert.Blob)
		if err != nil {
			return nil, nil, fmt.Errorf("decode chain cert blob: %w", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		})
		chainPEM = append(chainPEM, certPEM...)
	}

	return leafPEM, chainPEM, nil
}
