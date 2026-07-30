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

// main is the entry point for the digicert-issuer controller manager.
//
// High-level architecture:
//
//	cert-manager watches for CertificateRequest resources. When a request
//	references a DigiCertIssuer or DigiCertClusterIssuer, issuer-lib's
//	CombinedController picks it up and delegates to our signer.DigiCertSigner:
//
//	  cert-manager CertificateRequest
//	        │
//	        ▼
//	  issuer-lib CombinedController   ← registered here via SetupWithManager
//	        │
//	        ├─ Check(ctx, issuer)     → DigiCertSigner.Check  → CA health check
//	        └─ Sign(ctx, cr, issuer) → DigiCertSigner.Sign   → CA sign request
//
//	The controller manager (ctrl.Manager) handles:
//	  - Kubernetes API client lifecycle
//	  - Leader election (one active replica at a time)
//	  - Health/readiness probes
//	  - Prometheus metrics endpoint
//	  - Graceful shutdown on SIGTERM/SIGINT
package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	// Blank import: registers all Kubernetes cloud-provider auth plugins
	// (Azure, GCP, OIDC, etc.) so the controller can authenticate to any
	// cluster without extra configuration.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerv1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"

	apiv1alpha1 "digicert-issuer/api/v1alpha1"
	"digicert-issuer/internal/signer"
	// +kubebuilder:scaffold:imports
	// ↑ Do not remove this marker — the kubebuilder CLI injects new import
	// lines here when you run `kubebuilder create api` or `kubebuilder create webhook`.
)

// scheme is the runtime type registry for this controller.
// Every Kubernetes resource type the controller reads or writes must be
// registered here so the API machinery knows how to encode/decode it.
var (
	scheme = runtime.NewScheme()

	// setupLog is a structured logger scoped to the startup phase.
	// Once the manager starts, controllers use log.FromContext(ctx) instead.
	setupLog = ctrl.Log.WithName("setup")
)

// init runs before main and registers types into the global scheme.
// It must complete before any controller tries to talk to the API server.
func init() {
	// Register all core Kubernetes types (Pod, Deployment, Secret, etc.)
	// so the controller can read Secrets for auth credentials.
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	// Register cert-manager API types (CertificateRequest, etc.) required by
	// issuer-lib controllers.
	utilruntime.Must(cmapi.AddToScheme(scheme))

	// Note: issuer-lib's v1alpha1 package (issuerv1alpha1) only exposes shared
	// Go interfaces/types (Issuer, IssuerStatus) — it has no CRD types or
	// AddToScheme of its own to register. IssuerStatus is embedded directly in
	// our own DigiCertIssuer/DigiCertClusterIssuer types below.

	// Register our own CRD types: DigiCertIssuer and DigiCertClusterIssuer.
	// Defined in api/v1alpha1/; without this the manager would not recognise them.
	utilruntime.Must(apiv1alpha1.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
	// ↑ Do not remove — kubebuilder injects AddToScheme calls here for any
	// new API types created with `kubebuilder create api`.
}

func main() {
	// ── CLI Flags ──────────────────────────────────────────────────────────────
	//
	// All runtime configuration comes in through flags, following the Kubernetes
	// controller convention. There are no config files — flags only.
	// These values are read once at startup; changing them requires a pod restart.

	var metricsAddr string
	// Cert paths for the HTTPS metrics endpoint (TLS termination).
	var metricsCertPath, metricsCertName, metricsCertKey string
	// Cert paths for the webhook server (if webhooks are used in the future).
	var webhookCertPath, webhookCertName, webhookCertKey string
	// Whether to run leader election — must be true for multi-replica deployments.
	var enableLeaderElection bool
	// Address for the /healthz and /readyz HTTP probes (used by Kubernetes liveness/readiness checks).
	var probeAddr string
	// Whether to serve the Prometheus metrics endpoint over HTTPS (recommended in production).
	var secureMetrics bool
	// HTTP/2 is disabled by default — some Kubernetes proxy configurations
	// (e.g. older istio versions) don't handle h2 well on controller ports.
	var enableHTTP2 bool
	// Namespace used to resolve Secrets for DigiCertClusterIssuer resources.
	// ClusterIssuers are not namespaced, so we need an explicit namespace for their Secrets.
	var clusterResourceNamespace string
	// TLS option functions applied to both the metrics and webhook servers.
	var tlsOpts []func(*tls.Config)

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8084", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers.")
	flag.StringVar(&clusterResourceNamespace, "cluster-resource-namespace", "cert-manager",
		"The namespace used to fetch Secrets referenced by DigiCertClusterIssuer resources.")

	// zap is the structured logger used throughout controller-runtime.
	// Development mode enables human-readable output; production uses JSON.
	// Flags like --zap-log-level and --zap-encoder are added to flag.CommandLine here.
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// Wire the zap logger into controller-runtime's global logger.
	// All subsequent log.FromContext(ctx) calls will use this logger.
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// ── TLS Configuration ──────────────────────────────────────────────────────
	//
	// HTTP/2 is disabled unless explicitly enabled. The disableHTTP2 function is
	// passed as a TLS option that forces http/1.1 by clearing NextProtos.
	// This avoids known issues with some Kubernetes proxy configurations.
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// ── Webhook Server ─────────────────────────────────────────────────────────
	//
	// The webhook server handles admission webhooks (validation/mutation).
	// This controller does not currently register any webhooks, but the server
	// is scaffolded by kubebuilder and left in place for future use.
	// If a webhook cert path is provided, the server watches that directory
	// for cert rotation and reloads automatically.
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{TLSOpts: webhookTLSOpts}
	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher",
			"webhook-cert-path", webhookCertPath,
			"webhook-cert-name", webhookCertName,
			"webhook-cert-key", webhookCertKey)
		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}
	webhookServer := webhook.NewServer(webhookServerOptions)

	// ── Metrics Server ─────────────────────────────────────────────────────────
	//
	// The metrics server exposes Prometheus-format metrics at /metrics.
	// When secureMetrics=true (default), it requires a valid bearer token in
	// the request — enforced by filters.WithAuthenticationAndAuthorization.
	// This prevents unauthenticated scraping of potentially sensitive metrics.
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if secureMetrics {
		// Require the scraper to authenticate with the Kubernetes API server.
		// In practice this means your Prometheus ServiceAccount needs RBAC to
		// access the metrics endpoint (config/rbac/metrics_auth_role.yaml).
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher",
			"metrics-cert-path", metricsCertPath,
			"metrics-cert-name", metricsCertName,
			"metrics-cert-key", metricsCertKey)
		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	// ── Controller Manager ─────────────────────────────────────────────────────
	//
	// ctrl.Manager is the heart of a kubebuilder controller. It owns:
	//   - A shared Kubernetes API client (caches reads to reduce API server load)
	//   - The controller work queue
	//   - The leader election lock (Lease object in Kubernetes)
	//   - The metrics and webhook servers
	//   - The health/readiness probe endpoints
	//
	// ctrl.GetConfigOrDie() reads the kubeconfig from the environment:
	//   in-cluster: uses the pod's ServiceAccount token + CA cert
	//   local:      reads KUBECONFIG or ~/.kube/config
	//
	// LeaderElectionID is the name of the Kubernetes Lease object used as the
	// distributed lock. The hex prefix is a hash of the project name to avoid
	// collisions if multiple operators share the same namespace.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "9f7013bc.issuer.digicert.com",
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// ── Signer ─────────────────────────────────────────────────────────────────
	//
	// DigiCertSigner is our implementation of the issuer-lib Check and Sign
	// functions. It holds a reference to the manager's Kubernetes client
	// (used to read Secrets) and the namespace to use for ClusterIssuer Secrets.
	// It is constructed once here and shared across all reconcile calls — it is
	// stateless beyond these two fields.
	s := &signer.DigiCertSigner{
		Client:                   mgr.GetClient(),
		APIReader:                mgr.GetAPIReader(),
		ClusterResourceNamespace: clusterResourceNamespace,
	}

	// SetupSignalHandler returns a context that is cancelled when the process
	// receives SIGTERM or SIGINT. Passing this context to SetupWithManager and
	// mgr.Start ensures all goroutines shut down cleanly on pod termination.
	ctx := ctrl.SetupSignalHandler()

	// eventRecorder writes Kubernetes Events to CertificateRequest and Issuer
	// objects (visible via `kubectl describe`). The name "digicert-issuer"
	// appears in the "From" field of each event.
	eventRecorder := mgr.GetEventRecorder("digicert-issuer")

	// ── CombinedController ─────────────────────────────────────────────────────
	//
	// CombinedController (from cert-manager/issuer-lib) registers two reconcile
	// loops with the manager in a single call:
	//
	//   1. IssuerReconciler — watches DigiCertIssuer and DigiCertClusterIssuer.
	//      Calls s.Check() to verify the CA is reachable and sets the
	//      Ready status condition on the issuer resource.
	//
	//   2. RequestController — watches cert-manager CertificateRequest objects.
	//      When a request references one of our issuer types and the issuer is
	//      Ready, it calls s.Sign() to obtain the signed certificate and writes
	//      it back to the CertificateRequest status.
	//
	// Field meanings:
	//   IssuerTypes        — namespaced issuer types this controller manages
	//   ClusterIssuerTypes — cluster-scoped issuer types
	//   FieldOwner         — server-side-apply field manager name (appears in
	//                        object metadata, helps detect conflicts)
	//   MaxRetryDuration   — a CertificateRequest failing beyond this window
	//                        is marked permanently failed (no more retries)
	//   Check              — our CA health check function (signer.go)
	//   Sign               — our certificate signing function (signer.go)
	//   EventRecorder      — writes events to issuer and request objects
	//
	// DisableKubernetesCSRController is set because this issuer only supports
	// cert-manager CertificateRequest objects, not native Kubernetes
	// CertificateSigningRequest resources. Leaving the CSR controller enabled
	// (the issuer-lib default) makes the manager watch/list
	// certificates.k8s.io CertificateSigningRequests, which this project does
	// not grant RBAC for, causing repeated "Failed to watch" cache errors.
	if err := (&controllers.CombinedController{
		IssuerTypes:                    []issuerv1alpha1.Issuer{&apiv1alpha1.DigiCertIssuer{}},
		ClusterIssuerTypes:             []issuerv1alpha1.Issuer{&apiv1alpha1.DigiCertClusterIssuer{}},
		FieldOwner:                     "digicert-issuer",
		MaxRetryDuration:               5 * time.Minute,
		Check:                          s.Check,
		Sign:                           s.Sign,
		EventRecorder:                  eventRecorder,
		DisableKubernetesCSRController: true,
	}).SetupWithManager(ctx, mgr); err != nil {
		setupLog.Error(err, "Failed to set up CombinedController")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder
	// ↑ Do not remove — kubebuilder injects SetupWithManager calls here when
	// you add new controllers or webhooks via the CLI.

	// ── Health Probes ──────────────────────────────────────────────────────────
	//
	// Kubernetes uses these endpoints to determine if the pod is alive (liveness)
	// and ready to serve traffic (readiness). healthz.Ping is the simplest
	// implementation — it always returns 200 OK if the HTTP server is running.
	//
	// Registered at the paths /healthz and /readyz on the probeAddr port (:8084).
	// These map to the livenessProbe and readinessProbe in the Deployment manifest.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	// ── Start ──────────────────────────────────────────────────────────────────
	//
	// mgr.Start blocks until the context is cancelled (SIGTERM/SIGINT).
	// Internally it:
	//   1. Acquires the leader election Lease (if --leader-elect is set).
	//   2. Starts the shared informer cache (syncs all watched resources from the API server).
	//   3. Starts each registered controller's work queue.
	//   4. Starts the metrics and webhook servers.
	//   5. On shutdown: drains work queues, releases the Lease, stops goroutines.
	setupLog.Info("Starting manager",
		"cluster-resource-namespace", clusterResourceNamespace)
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
