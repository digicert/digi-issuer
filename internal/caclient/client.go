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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultTimeout = 20 * time.Second
)

// Client is an HTTP client for the DigiCert certificate-authority service.
type Client struct {
	baseURL    string
	auth       AuthProvider
	httpClient *http.Client
}

// New creates a new Client targeting the given base URL and using the provided
// AuthProvider for request authentication.
//
// When caBundlePEM is nil or empty, TLS verification is skipped
// (InsecureSkipVerify: true) for in-cluster communication without a bundle.
// When caBundlePEM is set, a custom cert pool is built from the PEM data and
// used as the RootCAs for TLS verification.
func New(baseURL string, auth AuthProvider, caBundlePEM []byte) (*Client, error) {
	tlsCfg := &tls.Config{}
	if len(caBundlePEM) == 0 {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional for in-cluster use without a CA bundle
	} else {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBundlePEM) {
			return nil, fmt.Errorf("failed to parse any certificates from CA bundle PEM")
		}
		tlsCfg.RootCAs = pool
	}

	return &Client{
		baseURL: baseURL,
		auth:    auth,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}, nil
}

// do performs an HTTP request against the CA service, injecting auth headers
// and decoding the JSON response body into out (if non-nil).
// Returns an error for non-2xx status codes.
func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	headerName, headerValue, err := c.auth.Header()
	if err != nil {
		return fmt.Errorf("build auth header: %w", err)
	}
	req.Header.Set(headerName, headerValue)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr apiError
		if jsonErr := json.Unmarshal(respBody, &apiErr); jsonErr == nil && apiErr.Message != "" {
			return fmt.Errorf("CA service returned %d: %s (code %d)", resp.StatusCode, apiErr.Message, apiErr.Code)
		}
		return fmt.Errorf("CA service returned %d: %s", resp.StatusCode, string(respBody))
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response body: %w", err)
		}
	}

	return nil
}
