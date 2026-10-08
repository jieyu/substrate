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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
)

// EgressTrustBundleName is the well-known name of the egress gateway CA
// bundle: the trust anchors for the per-SNI leaves the egress gateway
// mints, maintained by atecontroller from the egress-mitm-ca-pool via a
// trust-manager Bundle.
const (
	EgressTrustBundleName      = "egress-mitm.ate.dev"
	trustBundleConfigMapKey    = "trust-bundle.pem"
	trustBundleConfigNamespace = "ate-system"
)

// supportedTrustBundles maps the bundle names the trustBundle data source
// may reference to their backing trust-manager synced ConfigMaps in ate-system.
var supportedTrustBundles = map[string]string{
	EgressTrustBundleName: "egress-mitm-trust-bundle",
}

// supportedTrustBundleNames returns the allowlist, sorted, for error text.
func supportedTrustBundleNames() string {
	names := make([]string, 0, len(supportedTrustBundles))
	for name := range supportedTrustBundles {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// bundleNamesFor returns the allowlisted bundle names backed by the
// ConfigMap objectName.
func bundleNamesFor(objectName string) []string {
	var names []string
	for name, object := range supportedTrustBundles {
		if object == objectName {
			names = append(names, name)
		}
	}
	return names
}

// rawTrustBundle returns the unsanitized contents of the trust-manager synced
// ConfigMap backing the allowlisted bundle name.
func rawTrustBundle(lister corelisters.ConfigMapNamespaceLister, name string) (objectName, raw string, err error) {
	objectName, supported := supportedTrustBundles[name]
	if !supported {
		return "", "", fmt.Errorf("trust bundle %q is not supported by this deployment (supported: %s)", name, supportedTrustBundleNames())
	}
	cm, err := lister.Get(objectName)
	if apierrors.IsNotFound(err) {
		return "", "", fmt.Errorf("trust bundle %q: ConfigMap %q not found", name, objectName)
	} else if err != nil {
		return "", "", fmt.Errorf("trust bundle %q: while reading ConfigMap %q: %w", name, objectName, err)
	}
	return objectName, cm.Data[trustBundleConfigMapKey], nil
}

// trustBundleHash hashes the raw backing contents. The sanitized output is
// not comparable as anchors are shuffled on every call.
func trustBundleHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
