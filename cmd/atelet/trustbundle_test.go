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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certlisters "k8s.io/client-go/listers/certificates/v1beta1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// testCertPEM mints a throwaway self-signed certificate, PEM-encoded.
func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func ctbLister(t *testing.T, bundles ...*certsv1beta1.ClusterTrustBundle) certlisters.ClusterTrustBundleLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, b := range bundles {
		if err := indexer.Add(b); err != nil {
			t.Fatal(err)
		}
	}
	return certlisters.NewClusterTrustBundleLister(indexer)
}

func cmLister(t *testing.T, cms ...*corev1.ConfigMap) corelisters.ConfigMapNamespaceLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for _, cm := range cms {
		if err := indexer.Add(cm); err != nil {
			t.Fatal(err)
		}
	}
	return corelisters.NewConfigMapLister(indexer).ConfigMaps(trustBundleConfigNamespace)
}

const (
	// egressClusterTrustBundleObjectName is the backing ClusterTrustBundle in podcertificate mode.
	egressClusterTrustBundleObjectName = "egress-mitm.ate.dev:mitm:primary-bundle"
	// egressConfigMapTrustBundleObjectName is the backing ConfigMap in cert-manager mode.
	egressConfigMapTrustBundleObjectName = "egress-mitm-trust-bundle"
)

func TestRawTrustBundle(t *testing.T) {
	certPEM := testCertPEM(t)

	providers := []struct {
		name           string
		wantObjectName string
		sourceWith     func(t *testing.T, objectName, raw string) trustBundleSource
		emptySource    func(t *testing.T) trustBundleSource
	}{
		{
			name:           certProviderPodCertificate,
			wantObjectName: egressClusterTrustBundleObjectName,
			sourceWith: func(t *testing.T, objectName, raw string) trustBundleSource {
				return newClusterTrustBundleSource(ctbLister(t, &certsv1beta1.ClusterTrustBundle{
					ObjectMeta: metav1.ObjectMeta{Name: objectName},
					Spec:       certsv1beta1.ClusterTrustBundleSpec{TrustBundle: raw},
				}))
			},
			emptySource: func(t *testing.T) trustBundleSource {
				return newClusterTrustBundleSource(ctbLister(t))
			},
		},
		{
			name:           certProviderCertManager,
			wantObjectName: egressConfigMapTrustBundleObjectName,
			sourceWith: func(t *testing.T, objectName, raw string) trustBundleSource {
				return newConfigMapTrustBundleSource(cmLister(t, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: trustBundleConfigNamespace, Name: objectName},
					Data:       map[string]string{trustBundleConfigMapKey: raw},
				}))
			},
			emptySource: func(t *testing.T) trustBundleSource {
				return newConfigMapTrustBundleSource(cmLister(t))
			},
		},
	}

	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			t.Run("resolves the allowlisted name through the mapped object, unsanitized", func(t *testing.T) {
				raw := "garbage\n" + string(certPEM)
				source := p.sourceWith(t, p.wantObjectName, raw)
				objectName, got, err := source.raw(EgressTrustBundleName)
				if err != nil {
					t.Fatalf("raw: %v", err)
				}
				if objectName != p.wantObjectName {
					t.Errorf("objectName = %q, want %q", objectName, p.wantObjectName)
				}
				if got != raw {
					t.Errorf("raw = %q, want the backing contents verbatim", got)
				}
			})

			t.Run("unsupported bundle name fails naming it and the allowlist", func(t *testing.T) {
				source := p.sourceWith(t, "my-own-bundle", string(certPEM))
				_, _, err := source.raw("my-own-bundle")
				if err == nil || !strings.Contains(err.Error(), `"my-own-bundle"`) || !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), EgressTrustBundleName) {
					t.Errorf("error = %v, want unsupported-name error listing the allowlist", err)
				}
			})

			t.Run("missing bundle fails naming it", func(t *testing.T) {
				_, _, err := p.emptySource(t).raw(EgressTrustBundleName)
				if err == nil || !strings.Contains(err.Error(), p.wantObjectName) || !strings.Contains(err.Error(), "not found") {
					t.Errorf("error = %v, want not-found naming the backing object", err)
				}
			})
		})
	}
}
