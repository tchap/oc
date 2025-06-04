package regutil

import (
	"github.com/distribution/distribution/v3"
	"github.com/opencontainers/go-digest"
)

// ContentDigestForManifest returns the digest in the provided algorithm of the supplied manifest's contents.
func ContentDigestForManifest(manifest distribution.Manifest, algo digest.Algorithm) (digest.Digest, error) {
	_, payload, err := manifest.Payload()
	if err != nil {
		return "", err
	}
	return algo.FromBytes(payload), nil
}
