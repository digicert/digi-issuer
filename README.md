# DigiCert Issuer for cert-manager

`digicert-issuer` is a Kubernetes external issuer for [cert-manager](https://cert-manager.io/). It lets cert-manager `Certificate` resources obtain certificates from the DigiCert certificate-authority service rather than from cert-manager's built-in issuers.

The controller provides two `issuer.digicert.com/v1alpha1` resources:

- `DigiCertIssuer` is namespaced. It can issue certificates for `Certificate` resources in the same namespace and reads its referenced Secrets from that namespace.
- `DigiCertClusterIssuer` is cluster-scoped. It can issue certificates from any namespace and reads its referenced Secrets from the controller's cluster-resource namespace, `cert-manager` by default.

For each configured issuer, the controller checks that the DigiCert CA is reachable and that its credentials are valid. A ready issuer handles cert-manager `CertificateRequest` resources, submits their CSRs to the CA, and returns the resulting certificate material to cert-manager. After a successful issuance it also records:

- `issuer.digicert.com/certificate-id` on the `CertificateRequest`, containing the certificate ID returned by the CA.
- `issuer.digicert.com/serial-number` on the owning `Certificate`, containing the returned leaf certificate serial number.

The controller supports API-key authentication (`x-api-key`, the default) and bearer-token authentication. It reads credentials on each check and signing operation, so rotating a referenced Secret takes effect without restarting the controller.

## Guide 1: Production Deployment and Operation

This guide is for cluster operators installing DigiCert Issuer as a cert-manager external issuer. Follow the sections in order: establish the prerequisites, deploy the controller, store credentials and trust material, create an issuer, and validate a real certificate request.

### Deployment Model

The controller runs as one deployment in the `digicert-issuer-system` namespace and watches cert-manager `CertificateRequest` resources across the cluster. It requires cluster-scoped RBAC because a `DigiCertClusterIssuer` may service certificate requests from any namespace.

Choose the issuer scope before creating credentials:

- Use `DigiCertClusterIssuer` for centrally managed CA credentials that can issue certificates in multiple namespaces. By default, its credential and CA-bundle Secrets must be in `cert-manager`.
- Use `DigiCertIssuer` when one team or namespace must own its own CA credentials. Its credential and CA-bundle Secrets must be in the same namespace as the issuer.

The value of the manager's `--cluster-resource-namespace` argument controls where ClusterIssuer Secrets are resolved. The checked-in deployment sets it to `cert-manager`. Change that argument only as part of a deliberate secret-management design, then put all ClusterIssuer Secrets in the replacement namespace.

### Production Prerequisites

Use the following versions and access before deploying:

- `kubectl` configured for the target cluster, with permission to install CRDs and deploy cluster-scoped RBAC. A cluster administrator is normally required for a first installation.
- cert-manager `v1.20.2` installed and ready in the target cluster. The controller must be installed after cert-manager's CRDs are available.
- A reachable DigiCert certificate-authority service, a valid issuing CA ID, and an API key or bearer token authorized to use it.
- The CA's PEM trust bundle when the service is reached through HTTPS. Treat this as required for production.
- An image registry reachable by the cluster nodes, plus permission for the target namespace to pull the controller image.

Do not place API keys, bearer tokens, or private trust bundles in Git. Create Kubernetes Secrets from protected local files or your secret-management workflow. The checked-in files under `config/samples/` are examples only and contain placeholder or environment-specific values.

### 1. Install cert-manager

Install cert-manager before installing this controller. For a pinned cert-manager installation, use:

```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.20.2/cert-manager.yaml
kubectl wait --for=condition=Available deployment/cert-manager-webhook \
    --namespace cert-manager --timeout=5m
```

Verify that the cert-manager controller, webhook, and CA injector are running:

```sh
kubectl get pods --namespace cert-manager
```

### 2. Build, Publish, and Deploy the Controller

Build and publish an image the cluster nodes can pull. Use an immutable release tag rather than `latest` for a production rollout.

```sh
export IMG=<REGISTRY>/digicert-issuer:<TAG>
make docker-build docker-push IMG="$IMG"
make install
make deploy IMG="$IMG"
kubectl rollout status deployment/digicert-issuer-controller-manager \
    --namespace digicert-issuer-system --timeout=3m
```

`make install` installs the issuer CRDs. `make deploy` applies the controller deployment, RBAC, metrics service, and supporting resources. Both commands use the active kubeconfig context, so confirm the context before running them:

```sh
kubectl config current-context
```

For a private image registry, configure the normal Kubernetes image-pull credentials before deployment. The supplied manager manifest uses `IfNotPresent`; update the manifest or your release overlay to meet your image-pinning and pull-policy requirements.

### 3. Store Credentials and TLS Trust

For a `DigiCertClusterIssuer`, create the credential Secret in `cert-manager`, or in the namespace selected by `--cluster-resource-namespace`. Store the API key in a protected local file rather than in shell history:

```sh
umask 077
printf '%s' '<DIGICERT_API_KEY>' > /tmp/digicert-api-key
kubectl create secret generic digicert-issuer-credentials \
    --namespace cert-manager \
    --from-file=api-key=/tmp/digicert-api-key
rm /tmp/digicert-api-key
```

For bearer authentication, create the same Secret with `--from-file=token=/path/to/token` and set `authMode: bearer` in the issuer resource.

Create a Secret containing the DigiCert CA's PEM trust bundle. The controller reads the bundle from the `ca.crt` key:

```sh
kubectl create secret generic digicert-ca-bundle \
    --namespace cert-manager \
    --from-file=ca.crt=/path/to/digicert-ca.pem
```

> **Security requirement:** When `caBundleSecretName` is omitted, the current client skips TLS certificate verification. Set `caBundleSecretName` for every HTTPS production endpoint. Use plain HTTP only on a tightly controlled, private network.

Credential and CA-bundle Secret contents are read during issuer checks and signing calls. Updating the referenced Secret therefore takes effect without restarting the manager, but operators should validate a new credential using a controlled certificate request after rotation.

### 4. Create and Validate a ClusterIssuer

Create a `DigiCertClusterIssuer` for a centrally managed issuer. Replace every placeholder and retain the CA bundle field for a verified HTTPS connection:

```yaml
apiVersion: issuer.digicert.com/v1alpha1
kind: DigiCertClusterIssuer
metadata:
    name: digicert-production
spec:
    url: https://<DIGICERT_CA_HOST>/<BASE_PATH>
    authSecretName: digicert-issuer-credentials
    authMode: apiKey
    issuerID: <ISSUING_CA_UUID>
    accountID: <OPTIONAL_ACCOUNT_UUID>
    templateID: <OPTIONAL_TEMPLATE_UUID>
    caBundleSecretName: digicert-ca-bundle
```

```sh
kubectl apply -f digicert-clusterissuer.yaml
kubectl wait --for=condition=Ready digicertclusterissuer/digicert-production \
    --timeout=2m
kubectl get digicertclusterissuer digicert-production
```

The issuer condition is the first operational health check: it confirms that the controller can reach the DigiCert CA and authenticate. If it does not become ready, inspect the resource status and manager logs:

```sh
kubectl describe digicertclusterissuer digicert-production
kubectl logs deployment/digicert-issuer-controller-manager \
    --namespace digicert-issuer-system --container manager
```

### 5. Issue a Certificate Through cert-manager

Use a permitted DNS name and template. cert-manager creates the `CertificateRequest`; this controller sends its CSR to DigiCert and cert-manager writes the returned certificate to the target Secret.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
    name: digicert-test-cert
    namespace: default
spec:
    secretName: digicert-test-cert-tls
    commonName: test.example.com
    dnsNames:
        - test.example.com
    issuerRef:
        group: issuer.digicert.com
        kind: DigiCertClusterIssuer
        name: digicert-production
```

```sh
kubectl apply -f test-certificate.yaml
kubectl wait --for=condition=Ready certificate/digicert-test-cert \
    --namespace default --timeout=3m
kubectl get secret digicert-test-cert-tls --namespace default
```

Inspect the created `CertificateRequest` for the DigiCert certificate ID and the `Certificate` for the returned leaf serial number:

```sh
kubectl get certificaterequest --namespace default
kubectl get certificaterequest <CERTIFICATE_REQUEST_NAME> --namespace default \
    -o jsonpath='{.metadata.annotations.issuer\.digicert\.com/certificate-id}{"\n"}'
kubectl get certificate digicert-test-cert --namespace default \
    -o jsonpath='{.metadata.annotations.issuer\.digicert\.com/serial-number}{"\n"}'
```

### Namespaced Issuer

Use `DigiCertIssuer` when issuer ownership and CA credentials must be isolated per namespace. Create both Secrets in that namespace, then apply:

```yaml
apiVersion: issuer.digicert.com/v1alpha1
kind: DigiCertIssuer
metadata:
    name: team-a-digicert
    namespace: team-a
spec:
    url: https://<DIGICERT_CA_HOST>/<BASE_PATH>
    authSecretName: digicert-issuer-credentials
    authMode: apiKey
    issuerID: <ISSUING_CA_UUID>
    templateID: <OPTIONAL_TEMPLATE_UUID>
    caBundleSecretName: digicert-ca-bundle
```

Certificates must reside in `team-a` and use this issuer reference:

```yaml
issuerRef:
    group: issuer.digicert.com
    kind: DigiCertIssuer
    name: team-a-digicert
```

## Guide 2: Development, Implementation, and Contribution

This guide is for contributors building, changing, and validating the controller. It uses the same issuer configuration as production, but the local Kind workflow lets contributors test an image before it is pushed to a registry. Values in angle brackets must be replaced with values for a non-production DigiCert CA.

### Developer Prerequisites

- Go `1.26.5` or later.
- Docker, or another compatible tool selected with `CONTAINER_TOOL`, for image builds.
- `kubectl` and Kind for local cluster and E2E work.
- Access to a non-production DigiCert CA when running the live integration matrix. Do not use production credentials for ordinary development.

The Makefile downloads pinned local build tools into `bin/` when needed. No global `controller-gen`, Kustomize, envtest, or golangci-lint installation is required.

### Implementation Map

- `api/v1alpha1/` defines the `DigiCertIssuer` and `DigiCertClusterIssuer` CRDs and their validation markers. Run `make manifests generate` after changing these types or markers.
- `internal/caclient/` implements credential loading, CA readiness checks, and certificate signing requests.
- `internal/signer/` connects issuer-lib reconciliation to the CA client and writes certificate ID and serial-number annotations after issuance.
- `cmd/main.go` configures the manager, issuer controllers, health probes, and the cluster-resource Secret namespace.
- `config/` contains Kustomize deployment, RBAC, CRD, and sample manifests. Generated CRDs and RBAC must be regenerated rather than edited directly.
- `test/e2e/` verifies isolated deployment behavior. `test/e2e-kubeconfig/` verifies real issuance against a configured DigiCert CA.

### Local Kind Workflow

#### 1. Create the cluster and install cert-manager

```sh
kind create cluster --name digicert-issuer-dev
kubectl config use-context kind-digicert-issuer-dev

kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.20.2/cert-manager.yaml
kubectl wait --for=condition=Available deployment/cert-manager-webhook \
    --namespace cert-manager --timeout=5m
```

Confirm that cert-manager is ready before continuing:

```sh
kubectl get pods --namespace cert-manager
```

#### 2. Build, load, and deploy the controller

Build the image with a local tag, load it into Kind, install the CRDs, and deploy the manager. The deployment runs in `digicert-issuer-system` and is configured to resolve ClusterIssuer Secrets from `cert-manager`.

```sh
export IMG=digicert-issuer:dev
make docker-build IMG="$IMG"
kind load docker-image "$IMG" --name digicert-issuer-dev

make install
make deploy IMG="$IMG"
kubectl rollout status deployment/digicert-issuer-controller-manager \
    --namespace digicert-issuer-system --timeout=3m
```

#### 3. Create the CA credentials and trust bundle

For a `DigiCertClusterIssuer`, create the Secret in `cert-manager`. Store the API key in a local file with restrictive permissions so it is not exposed in shell history:

```sh
umask 077
printf '%s' '<DIGICERT_API_KEY>' > /tmp/digicert-api-key
kubectl create secret generic digicert-issuer-credentials \
    --namespace cert-manager \
    --from-file=api-key=/tmp/digicert-api-key
rm /tmp/digicert-api-key
```

If the CA uses a private or internal TLS certificate, create the optional CA bundle Secret. The controller expects a PEM bundle at the `ca.crt` key:

```sh
kubectl create secret generic digicert-ca-bundle \
    --namespace cert-manager \
    --from-file=ca.crt=/path/to/digicert-ca.pem
```

> **Security note:** When `caBundleSecretName` is omitted, the current client intentionally skips TLS certificate verification. Use a `caBundleSecretName` for any HTTPS production endpoint. A plain HTTP endpoint should only be used on a tightly controlled, private network.

For bearer-token authentication, create the credential Secret with `--from-file=token=/path/to/token` and set `authMode: bearer` in the issuer manifest instead.

#### 4. Create a ClusterIssuer

Save the following manifest as `digicert-clusterissuer.yaml`, replacing every placeholder. Keep `caBundleSecretName` when the CA is accessed by HTTPS.

```yaml
apiVersion: issuer.digicert.com/v1alpha1
kind: DigiCertClusterIssuer
metadata:
    name: digicert-production
spec:
    url: https://<DIGICERT_CA_HOST>/<BASE_PATH>
    authSecretName: digicert-issuer-credentials
    authMode: apiKey
    issuerID: <ISSUING_CA_UUID>
    accountID: <OPTIONAL_ACCOUNT_UUID>
    templateID: <OPTIONAL_TEMPLATE_UUID>
    caBundleSecretName: digicert-ca-bundle
```

Apply it and wait until the controller has verified the endpoint and credentials:

```sh
kubectl apply -f digicert-clusterissuer.yaml
kubectl wait --for=condition=Ready digicertclusterissuer/digicert-production \
    --timeout=2m
kubectl get digicertclusterissuer digicert-production
```

If the issuer does not become ready, inspect its status and the controller logs:

```sh
kubectl describe digicertclusterissuer digicert-production
kubectl logs deployment/digicert-issuer-controller-manager \
    --namespace digicert-issuer-system --container manager
```

#### 5. Request and verify a certificate

Save the following as `test-certificate.yaml`. Replace the DNS name with a name permitted by the configured CA and template.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
    name: digicert-test-cert
    namespace: default
spec:
    secretName: digicert-test-cert-tls
    commonName: test.example.com
    dnsNames:
        - test.example.com
    issuerRef:
        group: issuer.digicert.com
        kind: DigiCertClusterIssuer
        name: digicert-production
```

```sh
kubectl apply -f test-certificate.yaml
kubectl wait --for=condition=Ready certificate/digicert-test-cert \
    --namespace default --timeout=3m

kubectl get secret digicert-test-cert-tls --namespace default
kubectl get certificate digicert-test-cert --namespace default \
    -o jsonpath='{.metadata.annotations.issuer\.digicert\.com/serial-number}{"\n"}'
kubectl get certificaterequest --namespace default
```

The final command lists the request created by cert-manager. Inspect it to retrieve the DigiCert certificate ID annotation:

```sh
kubectl get certificaterequest <CERTIFICATE_REQUEST_NAME> --namespace default \
    -o jsonpath='{.metadata.annotations.issuer\.digicert\.com/certificate-id}{"\n"}'
```

### Issuer Configuration Reference

Both issuer types use the same `spec` fields:

| Field | Required | Description |
| --- | --- | --- |
| `url` | Yes | Base URL of the DigiCert certificate-authority service. |
| `authSecretName` | Yes | Name of the credential Secret. It must contain `api-key` for `apiKey` mode or `token` for `bearer` mode. |
| `authMode` | No | `apiKey` (default) sends `x-api-key`; `bearer` sends `Authorization: Bearer <token>`. |
| `issuerID` | Yes | UUID of the issuing CA in the certificate-authority service. |
| `accountID` | No | Optional account UUID supplied to the CA while issuing. |
| `templateID` | No | Optional certificate-template UUID supplied to the CA while issuing. |
| `caBundleSecretName` | No | Secret containing the CA PEM bundle at `ca.crt`. Required in practice for verified HTTPS connections. |

### Build, Run, and Test

Run the focused checks before sending a change for review. `make build` is the baseline local validation because it regenerates artifacts, formats code, runs `go vet`, and compiles the manager:

```sh
make build       # Generate manifests and deepcopy code, format, vet, and build bin/manager
make run         # Run the controller against the current kubeconfig
make test        # Run non-E2E Go tests with envtest
make lint        # Run golangci-lint
make help        # List all supported targets
```

`make test-e2e` creates and removes an isolated Kind cluster, then verifies controller deployment, health, and protected metrics. It is not a DigiCert CA integration test.

`make test-e2e-kubeconfig` is the CA integration matrix. It runs against the active kubeconfig and requires a deployed controller, cert-manager, a ready `DigiCertClusterIssuer`, and the configured credential Secret. It creates and removes a temporary namespace whose name begins with `digicert-issuer-e2e-`, then verifies ClusterIssuer and namespaced-issuer issuance, reissuance, invalid credentials, credential rotation, and both metadata annotations.

```sh
make test-e2e-kubeconfig
```

Set these variables for a nondefault deployment:

```sh
E2E_CLUSTER_ISSUER=my-cluster-issuer \
E2E_CREDENTIALS_SECRET=my-credentials \
E2E_CREDENTIALS_NAMESPACE=my-credentials-namespace \
E2E_MANAGER_NAMESPACE=digicert-issuer-system \
make test-e2e-kubeconfig
```

### Contribution Workflow

1. Keep API changes in `api/v1alpha1/` and reconciliation or CA behavior changes in their owning `internal/` package. Do not edit generated files under `config/crd/bases/`, `config/rbac/role.yaml`, or `zz_generated.deepcopy.go`.
2. Update or add focused tests with the behavior change. Use `make test` for unit and envtest coverage; use `make test-e2e` for deployment behavior; run `make test-e2e-kubeconfig` only against a dedicated, non-production CA environment.
3. Run `make build` and `make lint` before requesting review. If types, validation markers, or RBAC markers changed, verify that generated output is included by running `make manifests generate`.
4. Keep credentials, bearer tokens, and private CA bundles out of source control and test fixtures. Sanitize any externally supplied values before use and never hardcode secrets in manifests or code.
5. Describe operational impact in the change: new RBAC, CRD changes, configuration migrations, TLS behavior, or required release steps.

## Uninstall

Delete the certificates and issuer resources that depend on the controller before removing it. Deleting CRDs removes all custom resources of those kinds.

```sh
kubectl delete certificate digicert-test-cert --namespace default --ignore-not-found
kubectl delete digicertclusterissuer digicert-production --ignore-not-found
make undeploy
make uninstall
```

For the local quick-start environment, remove the Kind cluster after uninstalling:

```sh
kind delete cluster --name digicert-issuer-dev
```

## Distribution

Generate a single install manifest after building and publishing the controller image:

```sh
make build-installer IMG=<REGISTRY>/digicert-issuer:<TAG>
```

This creates `dist/install.yaml`, which contains the CRDs, RBAC, and controller deployment. cert-manager and DigiCert credential/issuer resources remain external prerequisites and must be installed or created separately.

## License

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

