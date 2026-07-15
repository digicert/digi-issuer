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

import "fmt"

// AuthProvider supplies an HTTP header name and value for authenticating
// requests to the certificate-authority service.
type AuthProvider interface {
	// Header returns the header name and value to inject on each request.
	Header() (name, value string, err error)
}

// APIKeyAuth implements AuthProvider using a static API key.
// It sets the "x-api-key" header required by the CA's apiKey mode.
type APIKeyAuth struct {
	APIKey string
}

// Header returns the x-api-key header for apiKey authentication.
func (a *APIKeyAuth) Header() (string, string, error) {
	if a.APIKey == "" {
		return "", "", fmt.Errorf("apiKey auth: api key is empty")
	}
	return "x-api-key", a.APIKey, nil
}

// BearerAuth implements AuthProvider using a Bearer token.
// It sets the "Authorization: Bearer <token>" header for iJWT mode.
type BearerAuth struct {
	Token string
}

// Header returns the Authorization header for Bearer token authentication.
func (a *BearerAuth) Header() (string, string, error) {
	if a.Token == "" {
		return "", "", fmt.Errorf("bearer auth: token is empty")
	}
	return "Authorization", "Bearer " + a.Token, nil
}
