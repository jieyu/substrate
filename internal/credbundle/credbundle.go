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

// Package credbundle handles credential files written by cert-manager-csi-driver
// (separate tls.crt and tls.key files) as well as single-file PEM credential bundles.
//
// In a single-file bundle, the file contains a PRIVATE KEY block and one or more
// CERTIFICATE blocks in leaf-to-root order. When separate tls.crt and tls.key
// files are used (or a directory containing them is passed), tls.crt holds the
// CERTIFICATE blocks and tls.key holds the PKCS#8 PRIVATE KEY block.
package credbundle

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Loader reads a private key and certificate chain from path, which may be a
// single-file PEM credential bundle, a tls.crt file (paired with a sibling
// tls.key), or a directory containing tls.crt and tls.key as written by
// cert-manager-csi-driver.
//
// Returns a function that can be used as GetCertificate in a tls.Config. The parsed bundle is
// cached: each handshake stats the file(s) and re-reads them only when they have changed, so
// certificate rotations are picked up on the next handshake without paying the read and
// parse cost when nothing changed.
func Loader(path string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := &certCache{path: path}
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.get()
	}
}

// ClientLoader is the client-side counterpart to Loader. It returns a function
// suitable for use as GetClientCertificate in a tls.Config, caching the parsed
// bundle in the same way so that certificate rotations are picked up on
// the next handshake.
func ClientLoader(path string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := &certCache{path: path}
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return c.get()
	}
}

// certCache holds the parse of credential file(s) together with the stat
// of the file(s) it was parsed from, so unchanged files are not re-parsed on
// every TLS handshake.
type certCache struct {
	path string

	mu sync.Mutex
	// certFI and keyFI are the stats taken just before cert was parsed; nil
	// until the first successful parse. cert is served while fresh stats still
	// match them.
	certFI os.FileInfo
	keyFI  os.FileInfo
	cert   *tls.Certificate
}

func sameStat(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && b.ModTime().Equal(a.ModTime()) && b.Size() == a.Size()
}

func resolvePaths(path string) (certPath, keyPath string, certFI, keyFI os.FileInfo, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("while getting file info for credential bundle %q: %w", path, err)
	}
	if fi.IsDir() {
		certPath = filepath.Join(path, "tls.crt")
		keyPath = filepath.Join(path, "tls.key")
		certFI, err = os.Stat(certPath)
		if err != nil {
			return "", "", nil, nil, fmt.Errorf("while getting file info for certificate %q: %w", certPath, err)
		}
		keyFI, err = os.Stat(keyPath)
		if err != nil {
			return "", "", nil, nil, fmt.Errorf("while getting file info for private key %q: %w", keyPath, err)
		}
		return certPath, keyPath, certFI, keyFI, nil
	}
	if filepath.Base(path) == "tls.crt" {
		siblingKey := filepath.Join(filepath.Dir(path), "tls.key")
		if kfi, kerr := os.Stat(siblingKey); kerr == nil && !kfi.IsDir() {
			return path, siblingKey, fi, kfi, nil
		}
	}
	return path, "", fi, nil, nil
}

// get returns the parsed bundle, re-reading the file(s) only when they have changed
// since the last successful parse.
//
// A change is any difference in file identity (os.SameFile: device and inode
// on Unix), modification time, or size. Both projected volumes and
// cert-manager-csi-driver rotate contents atomically via symlinks or renames,
// which surfaces here as a change of file identity; mtime and size additionally
// cover in-place rewrites.
func (c *certCache) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	certPath, keyPath, certFI, keyFI, err := resolvePaths(c.path)
	if err != nil {
		return nil, err
	}
	if c.cert != nil && sameStat(c.certFI, certFI) && sameStat(c.keyFI, keyFI) {
		return c.cert, nil
	}

	cert, err := parseFiles(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	c.certFI, c.keyFI, c.cert = certFI, keyFI, cert
	return cert, nil
}

// Parse reads a private key and certificate chain from bundlePath, which may be
// a single-file PEM bundle, a tls.crt file (with a sibling tls.key), or a
// directory containing tls.crt and tls.key.
func Parse(bundlePath string) (*tls.Certificate, error) {
	certPath, keyPath, _, _, err := resolvePaths(bundlePath)
	if err != nil {
		return nil, err
	}
	return parseFiles(certPath, keyPath)
}

func parseFiles(certPath, keyPath string) (*tls.Certificate, error) {
	bundleBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("while reading credential bundle: %w", err)
	}
	if keyPath != "" {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("while reading private key %q: %w", keyPath, err)
		}
		bundleBytes = append(bundleBytes, '\n')
		bundleBytes = append(bundleBytes, keyBytes...)
	}

	var leafKeyBytes []byte
	var chainBytes [][]byte

	for {
		var block *pem.Block
		block, bundleBytes = pem.Decode(bundleBytes)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			chainBytes = append(chainBytes, block.Bytes)
		case "PRIVATE KEY":
			leafKeyBytes = block.Bytes
		default:
			return nil, fmt.Errorf("unknown PEM block type %q", block.Type)
		}
	}

	if leafKeyBytes == nil {
		return nil, fmt.Errorf("no PRIVATE KEY block found")
	}

	if len(chainBytes) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found")
	}

	leafKey, err := x509.ParsePKCS8PrivateKey(leafKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("while parsing private key: %w", err)
	}

	leafCert, err := x509.ParseCertificate(chainBytes[0])
	if err != nil {
		return nil, fmt.Errorf("while parsing leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: chainBytes,
		Leaf:        leafCert,
		PrivateKey:  leafKey,
	}, nil
}
