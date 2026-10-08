// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package steps

import (
	"context"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/log"
)

// trustBundleNames are the trust bundle ConfigMaps trust-manager publishes in
// ate-system once it is running.
var trustBundleNames = []string{
	"podidentity-trust-bundle",
	"servicedns-trust-bundle",
}

// EnsureAPIServerPrerequisites creates the secrets and config ate-api-server
// needs, skipping anything already present.
func (e *Env) EnsureAPIServerPrerequisites(ctx context.Context) error {
	log.Step("ensure_apiserver_prerequisites")

	if err := e.ensureSecret(ctx, NamespaceAteSystem, SecretActorIDJWTPool, e.CreateJWTAuthorityPoolSecret); err != nil {
		return err
	}
	if err := e.ensureSecret(ctx, NamespaceAteSystem, SecretActorIDCAPool, e.CreateActorIDCAPoolSecret); err != nil {
		return err
	}
	// Derived from actor-id-ca-pool above, so it must come after it.
	if err := e.ensureSecret(ctx, NamespaceAteSystem, SecretActorIDCACerts, e.CreateActorIDCACertsSecret); err != nil {
		return err
	}
	// Always reconcile the PostgreSQL connection settings, so that a changed
	// ATE_API_POSTGRES_CONNECTION_STRING reaches an existing install.
	if err := e.CreateAPIServerEnvVars(ctx); err != nil {
		return err
	}

	exists, err := e.Kube.ConfigMapExists(ctx, NamespaceAteSystem, ConfigMapAPIAuthn)
	if err != nil {
		return err
	}
	if !exists {
		return e.CreateAPIAuthenticationConfig(ctx)
	}
	return nil
}

// EnsureCertManager installs cert-manager, cert-manager-csi-driver,
// trust-manager, and the Substrate ClusterIssuers and Bundles, then waits for
// trust-manager to publish both trust bundle ConfigMaps in ate-system.
func (e *Env) EnsureCertManager(ctx context.Context) error {
	log.Step("ensure_cert_manager")

	if err := e.Kube.EnsureNamespace(ctx, NamespaceAteSystem); err != nil {
		return err
	}
	if err := e.Kube.EnsureNamespace(ctx, NamespaceCertManager); err != nil {
		return err
	}

	timeout := e.Cfg.WaitTimeout(BootstrapTimeout)

	if err := e.Kube.ApplyPath(ctx, e.Cfg.Path("hack", "third_party", "cert-manager", "deploy", "cert-manager.yaml")); err != nil {
		return err
	}
	for _, name := range []string{"cert-manager", "cert-manager-cainjector", "cert-manager-webhook"} {
		if err := e.Kube.RolloutStatus(ctx, kube.KindDeployment, NamespaceCertManager, name, timeout); err != nil {
			return err
		}
	}

	if err := e.Kube.ApplyPath(ctx, e.Cfg.Path("hack", "third_party", "cert-manager", "deploy", "cert-manager-csi-driver.yaml")); err != nil {
		return err
	}
	if err := e.Kube.ApplyPath(ctx, e.Cfg.Path("hack", "third_party", "cert-manager", "deploy", "trust-manager.yaml")); err != nil {
		return err
	}
	if err := e.Kube.RolloutStatus(ctx, kube.KindDaemonSet, NamespaceCertManager, "cert-manager-csi-driver", timeout); err != nil {
		return err
	}
	if err := e.Kube.RolloutStatus(ctx, kube.KindDeployment, NamespaceCertManager, "trust-manager", timeout); err != nil {
		return err
	}

	if err := e.Kube.ApplyPath(ctx, e.Cfg.Manifest("cert-manager-issuers.yaml")); err != nil {
		return err
	}
	return e.WaitForTrustBundles(ctx)
}

// WaitForTrustBundles blocks until trust-manager has published both identity
// trust bundle ConfigMaps in ate-system.
func (e *Env) WaitForTrustBundles(ctx context.Context) error {
	log.Infof("Waiting for trust-manager trust bundle ConfigMaps to be ready...")
	return e.Kube.WaitTrustBundleConfigMaps(ctx, NamespaceAteSystem, trustBundleNames, e.Cfg.WaitTimeout(BootstrapTimeout))
}

// ensureSecret runs create when the named Secret is absent.
func (e *Env) ensureSecret(ctx context.Context, namespace, name string, create func(context.Context) error) error {
	exists, err := e.Kube.SecretExists(ctx, namespace, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return create(ctx)
}
