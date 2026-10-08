// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	certsv1beta1ac "k8s.io/client-go/applyconfigurations/certificates/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/agent-substrate/substrate/internal/localca"
)

// EgressMITMTrustReconciler derives either a ClusterTrustBundle (in
// podcertificate mode) or a trust-manager Bundle (in cert-manager mode) from
// the egress MITM CA pool.
type EgressMITMTrustReconciler struct {
	client.Client
	CertProvider CertProvider
}

// EgressMITMCAPoolRef names the Secret holding the CA pool the egress gateway's
// sdsmint sidecar signs per-SNI leaves with.
func EgressMITMCAPoolRef() types.NamespacedName {
	const egressMITMCAPoolSecret = "egress-mitm-ca-pool"
	return types.NamespacedName{Namespace: ateSystemNamespace, Name: egressMITMCAPoolSecret}
}

var trustBundleGVK = schema.GroupVersionKind{
	Group:   "trust.cert-manager.io",
	Version: "v1alpha1",
	Kind:    "Bundle",
}

//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=clustertrustbundles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,resourceNames=egress-mitm.ate.dev/*,verbs=attest
//+kubebuilder:rbac:groups=trust.cert-manager.io,resources=bundles,verbs=get;list;watch;create;update;patch;delete

func (r *EgressMITMTrustReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if k8errors.IsNotFound(err) {
			// The pool is gone, so the anchor goes with it. A cluster-scoped
			// trust bundle cannot take an OwnerReference on a namespaced Secret
			// -- cluster-scoped objects may not be owned by namespaced ones --
			// so nothing collects it for us, and a bundle left behind keeps
			// every consumer trusting a CA that no longer has an owner but
			// whose key may still exist somewhere.
			return ctrl.Result{}, r.deleteTrustBundle(ctx)
		}
		return ctrl.Result{}, fmt.Errorf("failed to get egress MITM CA pool %q: %w", req.NamespacedName, err)
	}
	if !secret.GetDeletionTimestamp().IsZero() {
		return ctrl.Result{}, r.deleteTrustBundle(ctx)
	}

	trustBundle, err := egressMITMTrustBundlePEM(secret)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to derive the egress MITM trust bundle from %q: %w", req.NamespacedName, err)
	}

	const egressMITMTrustFieldOwner = "ate-egress-mitm-trust"
	if effectiveCertProvider(r.CertProvider) == CertProviderCertManager {
		bundle := buildEgressMITMTrustBundle(trustBundle)
		if err := r.Patch(ctx, bundle, client.Apply, client.FieldOwner(egressMITMTrustFieldOwner), client.ForceOwnership); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to apply Bundle %q: %w", bundle.GetName(), err)
		}
		log.Info("reconciled the egress MITM trust bundle",
			"name", bundle.GetName(),
			"secret", req.NamespacedName.String())
		return ctrl.Result{}, nil
	}

	ctbAC := buildEgressMITMClusterTrustBundleApplyConfig(trustBundle)
	// Server-side apply rather than get-then-update: it creates and updates
	// through one call, and it reverts hand edits to the fields owned here
	// without clobbering anything a different manager legitimately set.
	if err := r.Apply(ctx, ctbAC, client.FieldOwner(egressMITMTrustFieldOwner), client.ForceOwnership); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to apply ClusterTrustBundle %q: %w", *ctbAC.Name, err)
	}
	log.Info("reconciled the egress MITM trust bundle",
		"name", *ctbAC.Name,
		"secret", req.NamespacedName.String())

	return ctrl.Result{}, nil
}

// egressMITMSignerName identifies the MITM CA's trust domain.
const (
	egressMITMSignerName             = "egress-mitm.ate.dev/mitm"
	egressMITMSignerLabel            = "ate.dev/signer"
	egressMITMTrustBundleKey         = "trust-bundle.pem"
	egressMITMClusterTrustBundleName = "egress-mitm.ate.dev:mitm:primary-bundle"
	egressMITMTrustBundleName        = "egress-mitm-trust-bundle"
)

func buildEgressMITMClusterTrustBundleApplyConfig(trustBundle string) *certsv1beta1ac.ClusterTrustBundleApplyConfiguration {
	return certsv1beta1ac.ClusterTrustBundle(egressMITMClusterTrustBundleName).
		WithLabels(map[string]string{
			"podcert.ate.dev/canarying": "live",
		}).
		WithSpec(certsv1beta1ac.ClusterTrustBundleSpec().
			WithSignerName(egressMITMSignerName).
			WithTrustBundle(trustBundle))
}

func buildEgressMITMTrustBundle(trustBundle string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "trust.cert-manager.io/v1alpha1",
			"kind":       "Bundle",
			"metadata": map[string]any{
				"name": egressMITMTrustBundleName,
				"labels": map[string]any{
					egressMITMSignerLabel:       egressMITMSignerName,
					"podcert.ate.dev/canarying": "live",
				},
			},
			"spec": map[string]any{
				"sources": []any{
					map[string]any{
						"inLine": trustBundle,
					},
				},
				"target": map[string]any{
					"configMap": map[string]any{
						"key": egressMITMTrustBundleKey,
					},
				},
			},
		},
	}
}

// egressMITMTrustBundlePEM renders the pool's root certificates, and nothing
// else, as a PEM blob.
func egressMITMTrustBundlePEM(secret *corev1.Secret) (string, error) {
	// The key `kubectl-ate admin make-ca-pool` writes the marshaled pool under.
	const egressMITMCAPoolKey = "pool"

	wire, ok := secret.Data[egressMITMCAPoolKey]
	if !ok {
		return "", fmt.Errorf("secret has no %q key", egressMITMCAPoolKey)
	}
	pool, err := localca.Unmarshal(wire)
	if err != nil {
		return "", fmt.Errorf("parsing the CA pool: %w", err)
	}
	if len(pool.CAs) == 0 {
		return "", fmt.Errorf("the CA pool contains no CAs")
	}

	var b strings.Builder
	for _, ca := range pool.CAs {
		if ca.RootCertificate == nil {
			return "", fmt.Errorf("CA %q has no root certificate", ca.ID)
		}
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: ca.RootCertificate.Raw}); err != nil {
			return "", fmt.Errorf("encoding the root certificate of CA %q: %w", ca.ID, err)
		}
	}
	return b.String(), nil
}

func (r *EgressMITMTrustReconciler) deleteTrustBundle(ctx context.Context) error {
	log := log.FromContext(ctx)

	if effectiveCertProvider(r.CertProvider) == CertProviderCertManager {
		bundle := &unstructured.Unstructured{}
		bundle.SetGroupVersionKind(trustBundleGVK)
		if err := r.Get(ctx, types.NamespacedName{Name: egressMITMTrustBundleName}, bundle); err != nil {
			if k8errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("failed to get Bundle %q: %w", egressMITMTrustBundleName, err)
		}

		if signer := bundle.GetLabels()[egressMITMSignerLabel]; signer != egressMITMSignerName {
			return fmt.Errorf("refusing to delete Bundle %q: signer is %q, not %q",
				egressMITMTrustBundleName, signer, egressMITMSignerName)
		}

		uid := bundle.GetUID()
		if err := r.Delete(ctx, bundle, client.Preconditions{UID: &uid}); err != nil && !k8errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete Bundle %q: %w", egressMITMTrustBundleName, err)
		}
		log.Info("deleted the egress MITM trust bundle; its CA pool is gone", "name", egressMITMTrustBundleName)
		return nil
	}

	ctb := &certsv1beta1.ClusterTrustBundle{}
	if err := r.Get(ctx, types.NamespacedName{Name: egressMITMClusterTrustBundleName}, ctb); err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get ClusterTrustBundle %q: %w", egressMITMClusterTrustBundleName, err)
	}

	if ctb.Spec.SignerName != egressMITMSignerName {
		return fmt.Errorf("refusing to delete ClusterTrustBundle %q: signer is %q, not %q",
			egressMITMClusterTrustBundleName, ctb.Spec.SignerName, egressMITMSignerName)
	}

	if err := r.Delete(ctx, ctb, client.Preconditions{UID: &ctb.UID}); err != nil && !k8errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete ClusterTrustBundle %q: %w", egressMITMClusterTrustBundleName, err)
	}
	log.Info("deleted the egress MITM trust bundle; its CA pool is gone", "name", egressMITMClusterTrustBundleName)
	return nil
}

func (r *EgressMITMTrustReconciler) SetupWithManager(mgr ctrl.Manager) error {
	poolRef := EgressMITMCAPoolRef()

	b := ctrl.NewControllerManagedBy(mgr).
		Named("egressmitmtrust").
		For(&corev1.Secret{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			return obj.GetNamespace() == poolRef.Namespace && obj.GetName() == poolRef.Name
		})))

	// The pool Secret is the only object reconciled from. The derived bundle is
	// watched as well so that deleting or hand-editing it is reverted rather
	// than silently accepted.
	if effectiveCertProvider(r.CertProvider) == CertProviderCertManager {
		watchedBundle := &unstructured.Unstructured{}
		watchedBundle.SetGroupVersionKind(trustBundleGVK)
		b = b.Watches(watchedBundle,
			handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: poolRef}}
			}),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetName() == egressMITMTrustBundleName
			})))
	} else {
		b = b.Watches(&certsv1beta1.ClusterTrustBundle{},
			handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: poolRef}}
			}),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetName() == egressMITMClusterTrustBundleName
			})))
	}

	return b.Complete(r)
}
