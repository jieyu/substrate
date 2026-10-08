//  Copyright 2026 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	certlisters "k8s.io/client-go/listers/certificates/v1beta1"
	corelisters "k8s.io/client-go/listers/core/v1"
)

// EgressTrustBundleName is the well-known name of the egress gateway CA
// bundle: the trust anchors for the per-SNI leaves the egress gateway
// mints, maintained by atecontroller from the egress-mitm-ca-pool.
const (
	EgressTrustBundleName      = "egress-mitm.ate.dev"
	trustBundleConfigMapKey    = "trust-bundle.pem"
	trustBundleConfigNamespace = "ate-system"

	certProviderPodCertificate = "podcertificate"
	certProviderCertManager    = "cert-manager"
)

// supportedClusterTrustBundles maps the bundle names the trustBundle data source
// may reference to their backing ClusterTrustBundles in podcertificate mode.
var supportedClusterTrustBundles = map[string]string{
	EgressTrustBundleName: "egress-mitm.ate.dev:mitm:primary-bundle",
}

// supportedConfigMapTrustBundles maps the bundle names the trustBundle data source
// may reference to their backing trust-manager synced ConfigMaps in ate-system
// in cert-manager mode.
var supportedConfigMapTrustBundles = map[string]string{
	EgressTrustBundleName: "egress-mitm-trust-bundle",
}

// supportedTrustBundleNames returns the allowlist, sorted, for error text.
func supportedTrustBundleNames(allowlist map[string]string) string {
	names := make([]string, 0, len(allowlist))
	for name := range allowlist {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// bundleNamesFor returns the allowlisted bundle names backed by objectName.
func bundleNamesFor(allowlist map[string]string, objectName string) []string {
	var names []string
	for name, object := range allowlist {
		if object == objectName {
			names = append(names, name)
		}
	}
	return names
}

// trustBundleSource abstracts reading and watching backing trust bundle objects
// across ClusterTrustBundle (podcertificate) and ConfigMap (cert-manager) modes.
type trustBundleSource interface {
	resourceKind() string
	raw(name string) (objectName, raw string, err error)
	bundleNamesForEvent(obj any) []string
}

type clusterTrustBundleSource struct {
	lister certlisters.ClusterTrustBundleLister
}

func newClusterTrustBundleSource(lister certlisters.ClusterTrustBundleLister) trustBundleSource {
	return &clusterTrustBundleSource{lister: lister}
}

func (s *clusterTrustBundleSource) resourceKind() string {
	return "ClusterTrustBundle"
}

func (s *clusterTrustBundleSource) raw(name string) (objectName, raw string, err error) {
	objectName, supported := supportedClusterTrustBundles[name]
	if !supported {
		return "", "", fmt.Errorf("trust bundle %q is not supported by this deployment (supported: %s)", name, supportedTrustBundleNames(supportedClusterTrustBundles))
	}
	bundle, err := s.lister.Get(objectName)
	if apierrors.IsNotFound(err) {
		return "", "", fmt.Errorf("trust bundle %q: ClusterTrustBundle %q not found", name, objectName)
	} else if err != nil {
		return "", "", fmt.Errorf("trust bundle %q: while reading ClusterTrustBundle %q: %w", name, objectName, err)
	}
	return objectName, bundle.Spec.TrustBundle, nil
}

func (s *clusterTrustBundleSource) bundleNamesForEvent(obj any) []string {
	ctb, ok := obj.(*certsv1beta1.ClusterTrustBundle)
	if !ok {
		return nil
	}
	return bundleNamesFor(supportedClusterTrustBundles, ctb.Name)
}

type configMapTrustBundleSource struct {
	lister corelisters.ConfigMapNamespaceLister
}

func newConfigMapTrustBundleSource(lister corelisters.ConfigMapNamespaceLister) trustBundleSource {
	return &configMapTrustBundleSource{lister: lister}
}

func (s *configMapTrustBundleSource) resourceKind() string {
	return "trust bundle ConfigMap"
}

func (s *configMapTrustBundleSource) raw(name string) (objectName, raw string, err error) {
	objectName, supported := supportedConfigMapTrustBundles[name]
	if !supported {
		return "", "", fmt.Errorf("trust bundle %q is not supported by this deployment (supported: %s)", name, supportedTrustBundleNames(supportedConfigMapTrustBundles))
	}
	cm, err := s.lister.Get(objectName)
	if apierrors.IsNotFound(err) {
		return "", "", fmt.Errorf("trust bundle %q: ConfigMap %q not found", name, objectName)
	} else if err != nil {
		return "", "", fmt.Errorf("trust bundle %q: while reading ConfigMap %q: %w", name, objectName, err)
	}
	return objectName, cm.Data[trustBundleConfigMapKey], nil
}

func (s *configMapTrustBundleSource) bundleNamesForEvent(obj any) []string {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil
	}
	return bundleNamesFor(supportedConfigMapTrustBundles, cm.Name)
}

// trustBundleHash hashes the raw backing contents. The sanitized output is
// not comparable as anchors are shuffled on every call.
func trustBundleHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
