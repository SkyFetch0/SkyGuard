package update

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// A release is trusted when the SHA-256 of its binary is listed in its
// SHA256SUMS and, when this build knows a signing key, SHA256SUMS carries a
// valid ed25519 signature from it (SHA256SUMS.sig, base64). The checksum
// alone proves the download arrived whole; the signature proves who made it,
// even if someone else could publish a release in the repository.

// TrustedKeys are the release signing keys compiled into this build
// (base64 ed25519 public keys). Add the project's key here once, so every
// build trusts it; update.public_key in the config adds one at run time.
var TrustedKeys = []string{}

// BuildKey is set with -ldflags "-X .../internal/update.BuildKey=<key>" by
// the release workflow, from the repository's SKYGUARD_UPDATE_PUBKEY.
var BuildKey = ""

// Keys returns the trusted keys: compiled in, from the build, and extra.
func Keys(extra ...string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, k := range append(append(append([]string{}, TrustedKeys...), BuildKey), extra...) {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%q is not a base64 ed25519 public key", k)
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out, nil
}

// SumFor finds name's checksum in a SHA256SUMS file ("<hex>  <name>").
func SumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS does not list %s", name)
}

// Verify checks a downloaded binary against the release's sums and, with
// keys, the signature over the sums.
func Verify(binary []byte, name string, sums, sig []byte, keys []ed25519.PublicKey) error {
	if len(keys) > 0 {
		if len(sig) == 0 {
			return errors.New("the release is not signed, and this build only installs signed releases")
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil {
			return errors.New("the release's signature is not base64")
		}
		ok := false
		for _, k := range keys {
			if ed25519.Verify(k, sums, raw) {
				ok = true
				break
			}
		}
		if !ok {
			return errors.New("the release's signature does not match any trusted key: it was not made by the project")
		}
	}
	want, err := SumFor(sums, name)
	if err != nil {
		return err
	}
	got := sha256.Sum256(binary)
	if hex.EncodeToString(got[:]) != want {
		return errors.New("the downloaded binary does not match its checksum: the download is damaged or was changed")
	}
	return nil
}

// GenerateKey makes a signing key pair, both base64.
func GenerateKey() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// Sign signs data with a base64 private key and returns the base64 signature.
func Sign(privateKey string, data []byte) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return "", errors.New("the signing key is not a base64 ed25519 private key")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(b), data)), nil
}
