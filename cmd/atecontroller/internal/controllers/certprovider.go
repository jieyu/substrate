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

// CertProvider selects how workload certificates and trust bundles are provisioned.
type CertProvider string

const (
	// CertProviderPodCertificate uses Kubernetes 1.36+ PodCertificateRequest and ClusterTrustBundle.
	CertProviderPodCertificate CertProvider = "podcertificate"
	// CertProviderCertManager uses cert-manager, cert-manager-csi-driver, and trust-manager.
	CertProviderCertManager CertProvider = "cert-manager"
)

// ValidCertProvider reports whether p is a supported CertProvider.
func ValidCertProvider(p CertProvider) bool {
	return p == CertProviderPodCertificate || p == CertProviderCertManager
}

// effectiveCertProvider normalizes an empty CertProvider to CertProviderPodCertificate.
func effectiveCertProvider(p CertProvider) CertProvider {
	if p == "" {
		return CertProviderPodCertificate
	}
	return p
}
