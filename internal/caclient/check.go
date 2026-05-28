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
	"fmt"
)

// CheckIssuer verifies that the certificate-authority service is reachable and
// that the configured credentials are valid by fetching the CA with the given
// issuerID. Returns a non-nil error if the CA cannot be reached, the
// credentials are rejected, or the CA ID is not found.
func (c *Client) CheckIssuer(ctx context.Context, issuerID string) error {
	if issuerID == "" {
		return fmt.Errorf("issuerID must not be empty")
	}

	var resp caResponse
	if err := c.do(ctx, "GET", "/certificate-authority/api/v1/ca/"+issuerID, nil, &resp); err != nil {
		return fmt.Errorf("check issuer %q: %w", issuerID, err)
	}

	return nil
}
