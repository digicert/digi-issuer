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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
)

// IssueCertificate sends the PEM-encoded PKCS#10 CSR to the certificate-authority
// service and returns the signed leaf certificate, chain as PEM bundles, and the
// CA-assigned certificate ID.
//
// Subject fields and SANs are extracted from the CSR and sent explicitly so the
// CA can apply them even when a template_id is used. The CSR is sent as-is with
// csr_type "csr".
//
// leafPEM contains the signed end-entity certificate.
// chainPEM contains the full issuing chain (leaf first, root last) as
// concatenated PEM blocks, suitable for use as the cert-manager PEMBundle.
// certID is the UUID assigned to the certificate by the CA.
func (c *Client) IssueCertificate(
	ctx context.Context,
	csrPEM []byte,
	issuerID string,
	accountID string,
	templateID string,
) (leafPEM []byte, chainPEM []byte, certID string, err error) {
	if len(csrPEM) == 0 {
		return nil, nil, "", fmt.Errorf("CSR must not be empty")
	}
	if issuerID == "" {
		return nil, nil, "", fmt.Errorf("issuerID must not be empty")
	}

	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, nil, "", err
	}

	reqBody := certificateRequest{
		TemplateID: templateID,
		Issuer:     certIssuer{ID: issuerID},
		AccountID:  accountID,
		CSR:        string(csrPEM),
		CSRType:    "csr",
		Subject:    subjectFromCSR(csr),
		Extensions: extensionsFromCSR(csr),
	}

	var resp certificateResponse
	headers := map[string]string{}
	if accountID != "" {
		// Hosted CA authorization resolves the active account from this header
		// before parsing the request body.
		headers["X-DC-AccountId"] = accountID
	}
	if err := c.doWithHeaders(ctx, "POST", "/api/v1/certificate", reqBody, headers, &resp); err != nil {
		return nil, nil, "", fmt.Errorf("issue certificate: %w", err)
	}

	if len(resp.Blob) == 0 {
		return nil, nil, "", fmt.Errorf("issue certificate: response contained empty blob")
	}

	// The CA returns the leaf cert as raw DER bytes in the Blob field.
	// pem.EncodeToMemory wraps it in a "-----BEGIN CERTIFICATE-----" PEM block.
	leafPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: resp.Blob,
	})

	// Assemble the full chain: leaf first, then any CA chain certificates.
	// Chain certs are returned as base64-encoded DER strings (not raw bytes),
	// so each one must be base64-decoded before PEM encoding.
	// The final chainPEM is a concatenated PEM bundle cert-manager uses as
	// the CertificateRequest's ca.crt / chain.
	chainPEM = append(chainPEM, leafPEM...)
	for _, chainCert := range resp.Chain {
		if chainCert.Blob == "" {
			continue
		}
		derBytes, err := base64.StdEncoding.DecodeString(chainCert.Blob)
		if err != nil {
			return nil, nil, "", fmt.Errorf("decode chain cert blob: %w", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		})
		chainPEM = append(chainPEM, certPEM...)
	}

	return leafPEM, chainPEM, resp.ID, nil
}

// parseCSR decodes a PEM-encoded PKCS#10 CSR and returns the parsed structure.
func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, nil
}

// subjectFromCSR extracts the X.509 subject fields from a parsed CSR.
// Returns nil if no meaningful subject fields are present.
func subjectFromCSR(csr *x509.CertificateRequest) *certSubject {
	s := &certSubject{
		CommonName:       csr.Subject.CommonName,
		OrganizationUnit: csr.Subject.OrganizationalUnit,
		StreetAddress:    csr.Subject.StreetAddress,
	}
	if len(csr.Subject.Organization) > 0 {
		s.OrganizationName = csr.Subject.Organization[0]
	}
	if len(csr.Subject.Locality) > 0 {
		s.Locality = csr.Subject.Locality[0]
	}
	if len(csr.Subject.Province) > 0 {
		s.State = csr.Subject.Province[0]
	}
	if len(csr.Subject.Country) > 0 {
		s.Country = csr.Subject.Country[0]
	}
	if len(csr.Subject.PostalCode) > 0 {
		s.PostalCode = csr.Subject.PostalCode[0]
	}
	if s.CommonName == "" && s.OrganizationName == "" && len(s.OrganizationUnit) == 0 {
		return nil
	}
	return s
}

// extensionsFromCSR extracts SANs from a parsed CSR.
// Returns nil if no SANs are present.
func extensionsFromCSR(csr *x509.CertificateRequest) *certExtensions {
	san := &certSAN{DNSNames: csr.DNSNames}
	for _, ip := range csr.IPAddresses {
		san.IPAddresses = append(san.IPAddresses, net.IP(ip).String())
	}
	if len(san.DNSNames) == 0 && len(san.IPAddresses) == 0 {
		return nil
	}
	return &certExtensions{SAN: san}
}
