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

// certIssuer is the issuer reference sent in a certificate signing request.
type certIssuer struct {
	ID string `json:"id"`
}

// certSubject holds the X.509 subject fields extracted from the CSR.
type certSubject struct {
	CommonName       string   `json:"common_name,omitempty"`
	OrganizationName string   `json:"organization_name,omitempty"`
	OrganizationUnit []string `json:"organization_unit,omitempty"`
	Locality         string   `json:"locality,omitempty"`
	State            string   `json:"state,omitempty"`
	Country          string   `json:"country,omitempty"`
	StreetAddress    []string `json:"street_address,omitempty"`
	PostalCode       string   `json:"postal_code,omitempty"`
}

// certSAN holds Subject Alternative Name values extracted from the CSR.
type certSAN struct {
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
}

// certExtensions holds certificate extensions derived from the CSR.
type certExtensions struct {
	SAN *certSAN `json:"san,omitempty"`
}

// certificateRequest is the JSON body sent to POST /api/v1/certificate.
type certificateRequest struct {
	// TemplateID is the certificate template UUID.
	TemplateID string `json:"template_id"`
	// Issuer identifies the CA within the certificate-authority service.
	Issuer certIssuer `json:"issuer"`
	// AccountID is the account UUID associated with the request.
	AccountID string `json:"account_id"`
	// CSR is the PEM-encoded PKCS#10 certificate signing request.
	CSR string `json:"csr"`
	// CSRType indicates the format of the CSR field: "csr" for a full PKCS#10
	// CSR, or "spki" for a raw SubjectPublicKeyInfo.
	CSRType string `json:"csr_type"`
	// Subject contains the X.509 subject fields for the certificate.
	Subject *certSubject `json:"subject,omitempty"`
	// Extensions contains SANs and other extensions derived from the CSR.
	Extensions *certExtensions `json:"extensions,omitempty"`
}

// chainCertificate represents a single certificate in the chain returned by the CA.
// The Blob field contains a base64-encoded DER certificate.
type chainCertificate struct {
	CertType string `json:"cert_type,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// certificateResponse is the JSON body returned by POST /api/v1/certificate.
type certificateResponse struct {
	// ID is the UUID assigned to the issued certificate by the CA.
	ID string `json:"id,omitempty"`
	// Blob is the base64-encoded DER-encoded leaf certificate.
	Blob []byte `json:"blob,omitempty"`
	// SerialNumber is the hex-encoded serial number of the issued certificate.
	SerialNumber string `json:"serial_number,omitempty"`
	// Chain contains the issuing chain certificates (excluding the leaf).
	Chain []chainCertificate `json:"chain,omitempty"`
}

// apiError represents an error response from the certificate-authority service.
type apiError struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}
