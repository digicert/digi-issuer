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
// healthy. Returns a non-nil error if the health endpoint cannot be reached or
// returns a non-2xx response.
func (c *Client) CheckIssuer(ctx context.Context, issuerID string) error {
	if err := c.do(ctx, "GET", "/api/v1/health", nil, nil); err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	return nil
}
