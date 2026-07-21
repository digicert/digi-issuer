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

package signer

import (
	"context"
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateMetadataReconciler writes CA metadata after issuer-lib marks a
// CertificateRequest Ready. It intentionally does not mutate pending requests.
type CertificateMetadataReconciler struct {
	Client client.Client
	Signer *DigiCertSigner
}

func (r *CertificateMetadataReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	certificateRequest := &cmapi.CertificateRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, certificateRequest); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !isReady(certificateRequest.Status.Conditions) {
		return ctrl.Result{}, nil
	}

	outcome, ok := r.Signer.issuanceOutcomes.Load(certificateRequest.UID)
	if !ok {
		return ctrl.Result{}, nil
	}
	issued := outcome.(issuanceOutcome)
	if err := r.applyMetadata(ctx, certificateRequest, issued); err != nil {
		return ctrl.Result{}, err
	}
	r.Signer.issuanceOutcomes.Delete(certificateRequest.UID)
	return ctrl.Result{}, nil
}

func (r *CertificateMetadataReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("certificate-metadata").
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}

func (r *CertificateMetadataReconciler) applyMetadata(
	ctx context.Context,
	certificateRequest *cmapi.CertificateRequest,
	issued issuanceOutcome,
) error {
	if issued.certificateID != "" {
		if err := setAnnotation(ctx, r.Client, certificateRequest, AnnotationCertificateID, issued.certificateID); err != nil {
			return fmt.Errorf("annotate CertificateRequest: %w", err)
		}
	}
	if issued.serialNumber == "" {
		return nil
	}

	owner := certificateOwnerReference(certificateRequest.OwnerReferences)
	if owner == nil {
		return nil
	}
	certificate := &cmapi.Certificate{}
	if err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: certificateRequest.Namespace,
		Name:      owner.Name,
	}, certificate); err != nil {
		return fmt.Errorf("get owning Certificate: %w", err)
	}
	if certificate.UID != owner.UID {
		return nil
	}
	if err := setAnnotation(ctx, r.Client, certificate, AnnotationSerialNumber, issued.serialNumber); err != nil {
		return fmt.Errorf("annotate Certificate: %w", err)
	}
	return nil
}

func setAnnotation(ctx context.Context, kubeClient client.Client, object client.Object, key, value string) error {
	if object.GetAnnotations()[key] == value {
		return nil
	}
	patch := client.MergeFrom(object.DeepCopyObject().(client.Object))
	annotations := object.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[key] = value
	object.SetAnnotations(annotations)
	return kubeClient.Patch(ctx, object, patch)
}

func certificateOwnerReference(owners []metav1.OwnerReference) *metav1.OwnerReference {
	for _, owner := range owners {
		if owner.APIVersion == cmapi.SchemeGroupVersion.String() && owner.Kind == "Certificate" {
			return &owner
		}
	}
	return nil
}

func isReady(conditions []cmapi.CertificateRequestCondition) bool {
	for _, condition := range conditions {
		if condition.Type == cmapi.CertificateRequestConditionReady && condition.Status == cmmeta.ConditionTrue {
			return true
		}
	}
	return false
}
