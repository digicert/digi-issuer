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

// certificateRequest is the JSON body sent to POST /certificate-authority/api/v1/certificate.
type certificateRequest struct {
	// CSR is the PEM-encoded certificate signing request.
	CSR string `json:"csr"`
	// Issuer identifies the CA within the certificate-authority service.
	Issuer certIssuer `json:"issuer"`
	// TemplateID is an optional certificate template UUID.
	TemplateID string `json:"template_id,omitempty"`
}

// chainCertificate represents a single certificate in the chain returned by the CA.
// The Blob field contains a base64-encoded DER certificate.
type chainCertificate struct {
	CertType string `json:"cert_type,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// certificateResponse is the JSON body returned by POST /certificate-authority/api/v1/certificate.
type certificateResponse struct {
	// ID is the UUID assigned to the issued certificate.
	ID string `json:"id,omitempty"`
	// Blob is the base64-encoded DER-encoded leaf certificate.
	Blob []byte `json:"blob,omitempty"`
	// SerialNumber is the hex-encoded serial number of the issued certificate.
	SerialNumber string `json:"serial_number,omitempty"`
	// Chain contains the issuing chain certificates (excluding the leaf).
	Chain []chainCertificate `json:"chain,omitempty"`
}

// caResponse is the JSON body returned by GET /certificate-authority/api/v1/ca/{id}.
// Only the fields needed for health checking are included.
type caResponse struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
}

// apiError represents an error response from the certificate-authority service.
type apiError struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}
