package sshkey

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
)

var (
	ErrInvalidDigest = fmt.Errorf("sshkey: invalid digest algorithm")
)

// Return the fingerprint of the key in a raw format.
func Fingerprint(pub *SSHPublicKey, hashalgo crypto.Hash) (fpr []byte, err error) {
	var h hash.Hash

	// The default algorithm for OpenSSH appears to be MD5.
	if hashalgo == 0 {
		hashalgo = crypto.MD5
	}

	switch hashalgo {
	case crypto.MD5:
		h = md5.New()
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	default:
		return nil, ErrInvalidDigest
	}

	blob, err := publicToBlob(pub)
	if err != nil {
		return nil, err
	}
	h.Write(blob)

	return h.Sum(nil), nil
}

// Return a string containing a printable form of the key's fingerprint.
func FingerprintPretty(pub *SSHPublicKey, hashalgo crypto.Hash) (fpr string, err error) {
	fprBytes, err := Fingerprint(pub, hashalgo)
	if err != nil {
		return
	}

	for _, v := range fprBytes {
		fpr += fmt.Sprintf("%02x:", v)
	}
	fpr = fpr[:len(fpr)-1]
	return
}
