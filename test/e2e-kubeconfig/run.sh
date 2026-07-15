#!/usr/bin/env bash

set -euo pipefail

kubectl_bin="${KUBECTL:-kubectl}"
cluster_issuer="${E2E_CLUSTER_ISSUER:-digicertclusterissuer-sample}"
credentials_secret="${E2E_CREDENTIALS_SECRET:-digicert-issuer-credentials}"
credentials_namespace="${E2E_CREDENTIALS_NAMESPACE:-}"
namespace="${E2E_NAMESPACE:-digicert-issuer-e2e-$(date +%s)}"
timeout="${E2E_TIMEOUT:-3m}"
manager_namespace="${E2E_MANAGER_NAMESPACE:-digicert-issuer-system}"
manager_deployment="${E2E_MANAGER_DEPLOYMENT:-digicert-issuer-controller-manager}"
temporary_directory="$(mktemp -d)"

cleanup() {
  "$kubectl_bin" delete namespace "$namespace" --ignore-not-found --wait=false
  rm -rf "$temporary_directory"
}

require() {
  local description="$1"
  shift
  if ! "$@"; then
    echo "E2E prerequisite failed: $description" >&2
    exit 1
  fi
}

wait_for_certificate() {
  local certificate_name="$1"
  "$kubectl_bin" wait --for=condition=Ready "certificate/${certificate_name}" \
    -n "$namespace" --timeout="$timeout"
}

certificate_serial() {
  "$kubectl_bin" get secret "$1" -n "$namespace" \
    -o jsonpath='{.data.tls\.crt}' | base64 --decode | openssl x509 -noout -serial
}

apply_certificate() {
  local name="$1"
  local secret_name="$2"
  local issuer_kind="$3"
  local issuer_name="$4"
  cat <<EOF | "$kubectl_bin" apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  secretName: ${secret_name}
  commonName: ${name}.${namespace}.example.com
  dnsNames:
    - ${name}.${namespace}.example.com
  issuerRef:
    group: issuer.digicert.com
    kind: ${issuer_kind}
    name: ${issuer_name}
EOF
}

trap cleanup EXIT

context="$("$kubectl_bin" config current-context)"
echo "Running E2E matrix against kubeconfig context: $context"
echo "Using ClusterIssuer: $cluster_issuer"

require "cert-manager Certificate CRD is installed" \
  "$kubectl_bin" get crd certificates.cert-manager.io
require "DigiCertClusterIssuer CRD is installed" \
  "$kubectl_bin" get crd digicertclusterissuers.issuer.digicert.com
require "the configured ClusterIssuer exists" \
  "$kubectl_bin" get digicertclusterissuer "$cluster_issuer"
require "the controller deployment is available" \
  "$kubectl_bin" rollout status "deployment/${manager_deployment}" -n "$manager_namespace" --timeout="$timeout"

if [[ -z "$credentials_namespace" ]]; then
  credentials_namespace="$("$kubectl_bin" get deployment "$manager_deployment" -n "$manager_namespace" \
    -o jsonpath='{range .spec.template.spec.containers[?(@.name=="manager")].args[*]}{.}{"\n"}{end}' |
    sed -n 's/^--cluster-resource-namespace=//p' | head -n 1)"
  credentials_namespace="${credentials_namespace:-cert-manager}"
fi
require "the credentials Secret exists in ${credentials_namespace}" \
  "$kubectl_bin" get secret "$credentials_secret" -n "$credentials_namespace"

issuer_url="$("$kubectl_bin" get digicertclusterissuer "$cluster_issuer" -o jsonpath='{.spec.url}')"
issuer_id="$("$kubectl_bin" get digicertclusterissuer "$cluster_issuer" -o jsonpath='{.spec.issuerID}')"
account_id="$("$kubectl_bin" get digicertclusterissuer "$cluster_issuer" -o jsonpath='{.spec.accountID}')"
template_id="$("$kubectl_bin" get digicertclusterissuer "$cluster_issuer" -o jsonpath='{.spec.templateID}')"
auth_mode="$("$kubectl_bin" get digicertclusterissuer "$cluster_issuer" -o jsonpath='{.spec.authMode}')"
auth_mode="${auth_mode:-apiKey}"
credential_key="api-key"
if [[ "$auth_mode" == "bearer" ]]; then
  credential_key="token"
fi

if [[ -z "$issuer_url" || -z "$issuer_id" ]]; then
  echo "E2E prerequisite failed: ClusterIssuer must define spec.url and spec.issuerID" >&2
  exit 1
fi
if [[ "$namespace" != digicert-issuer-e2e-* ]]; then
  echo "E2E_NAMESPACE must begin with digicert-issuer-e2e- to protect existing namespaces" >&2
  exit 1
fi

echo "Creating isolated matrix namespace: $namespace"
"$kubectl_bin" create namespace "$namespace"
credential_file="${temporary_directory}/${credential_key}"
"$kubectl_bin" get secret "$credentials_secret" -n "$credentials_namespace" \
  -o "jsonpath={.data.${credential_key}}" | base64 --decode > "$credential_file"
if [[ ! -s "$credential_file" ]]; then
  echo "E2E prerequisite failed: credentials Secret is missing a non-empty ${credential_key} key" >&2
  exit 1
fi
"$kubectl_bin" create secret generic "$credentials_secret" -n "$namespace" \
  "--from-file=${credential_key}=${credential_file}"

cat <<EOF | "$kubectl_bin" apply -f -
apiVersion: issuer.digicert.com/v1alpha1
kind: DigiCertIssuer
metadata:
  name: matrix-issuer
  namespace: ${namespace}
spec:
  url: ${issuer_url}
  authSecretName: ${credentials_secret}
  authMode: ${auth_mode}
  issuerID: ${issuer_id}
  accountID: ${account_id}
  templateID: ${template_id}
EOF

echo "Matrix: ClusterIssuer issuance"
apply_certificate cluster-issuer cluster-issuer-tls DigiCertClusterIssuer "$cluster_issuer"
wait_for_certificate cluster-issuer
"$kubectl_bin" get secret cluster-issuer-tls -n "$namespace" \
  -o jsonpath='{.data.tls\.crt}{.data.tls\.key}' | grep -q .

echo "Matrix: namespaced DigiCertIssuer issuance"
"$kubectl_bin" wait --for=condition=Ready digicertissuer/matrix-issuer -n "$namespace" --timeout="$timeout"
apply_certificate namespaced-issuer namespaced-issuer-tls DigiCertIssuer matrix-issuer
wait_for_certificate namespaced-issuer
"$kubectl_bin" get secret namespaced-issuer-tls -n "$namespace" \
  -o jsonpath='{.data.tls\.crt}{.data.tls\.key}' | grep -q .

echo "Matrix: reissuance after output Secret deletion"
first_serial="$(certificate_serial cluster-issuer-tls)"
"$kubectl_bin" delete certificate cluster-issuer -n "$namespace"
"$kubectl_bin" delete secret cluster-issuer-tls -n "$namespace"
apply_certificate cluster-issuer cluster-issuer-tls DigiCertClusterIssuer "$cluster_issuer"
wait_for_certificate cluster-issuer
second_serial="$(certificate_serial cluster-issuer-tls)"
if [[ "$first_serial" == "$second_serial" ]]; then
  echo "Expected reissuance to replace the certificate serial number" >&2
  exit 1
fi

echo "Matrix: invalid credentials fail without disrupting the controller"
"$kubectl_bin" create secret generic invalid-credentials -n "$namespace" \
  "--from-literal=${credential_key}=invalid-e2e-credential"
cat <<EOF | "$kubectl_bin" apply -f -
apiVersion: issuer.digicert.com/v1alpha1
kind: DigiCertIssuer
metadata:
  name: rotating-issuer
  namespace: ${namespace}
spec:
  url: ${issuer_url}
  authSecretName: invalid-credentials
  authMode: ${auth_mode}
  issuerID: ${issuer_id}
  accountID: ${account_id}
  templateID: ${template_id}
EOF
apply_certificate credential-rotation credential-rotation-tls DigiCertIssuer rotating-issuer
sleep 10
if "$kubectl_bin" get secret credential-rotation-tls -n "$namespace" >/dev/null 2>&1; then
  echo "Expected invalid credentials not to produce a TLS Secret" >&2
  exit 1
fi
"$kubectl_bin" rollout status "deployment/${manager_deployment}" -n "$manager_namespace" --timeout="$timeout"

echo "Matrix: credential rotation is used without restarting the controller"
"$kubectl_bin" delete secret invalid-credentials -n "$namespace"
"$kubectl_bin" create secret generic invalid-credentials -n "$namespace" \
  "--from-file=${credential_key}=${credential_file}"
"$kubectl_bin" delete certificate credential-rotation -n "$namespace"
apply_certificate credential-rotation credential-rotation-tls DigiCertIssuer rotating-issuer
wait_for_certificate credential-rotation

echo "Matrix: controller remains available after issuance"
"$kubectl_bin" rollout status "deployment/${manager_deployment}" -n "$manager_namespace" --timeout="$timeout"

echo "E2E matrix passed in namespace ${namespace}"