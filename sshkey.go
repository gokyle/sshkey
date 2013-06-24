/*
	sshkey is a package for loading OpenSSH keys from a file. Currently
	supports RSA and ECDSA keys.
*/
package sshkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"regexp"
)

var (
	ErrInvalidPublicKey  = fmt.Errorf("sshkey: invalid public key")
	ErrInvalidPrivateKey = fmt.Errorf("sshkey: invalid private key")
	ErrUnsupportedPublicKey = fmt.Errorf("sshkey: unsupported public key type")
	ErrUnsupportedPrivateKey = fmt.Errorf("sshkey: unsupported private key type")
)

// These constants are used as the keytype in functions that return a keytype.
const (
	KEY_UNSUPPORTED = -1
	KEY_ECDSA = iota
	KEY_RSA
)

var pubkeyRegexp = regexp.MustCompile("(?m)^[a-z0-9-]+ (\\S+).*$")

// fetchKey retrieves the raw data for a key, either via file or an HTTP get.
func fetchKey(name string, local bool) (kb []byte, err error) {
	if local {
		kb, err = ioutil.ReadFile(name)
	} else {
		var resp *http.Response
		resp, err = http.Get(name)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		kb, err = ioutil.ReadAll(resp.Body)
	}
	return
}

// LoadPublicKey loads an OpenSSH public key from a file or via HTTP. If
// local is false, the key will be fetched over HTTP.
func LoadPublicKeyFile(name string, local bool) (key interface{}, keytype int, err error) {
	kb64, err := fetchKey(name, local)
	return LoadPublicKey(kb64)
}

// LoadPublicKey decodes a byte slice containing an OpenSSH RSA public key
// into an RSA public key.
func LoadPublicKey(raw []byte) (key interface{}, keytype int, err error) {
	kb64 := pubkeyRegexp.ReplaceAll(raw, []byte("$1"))
	kb := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	_, err = base64.StdEncoding.Decode(kb, kb64)
	if err != nil {
		return
	}
	switch  {
	case bytes.HasPrefix(raw, []byte("ssh-rsa")):
		fmt.Println("load rsa key")
		keytype = KEY_RSA
		key, err = parseRSAPublicKey(kb)
	case bytes.HasPrefix(raw, []byte("ecdsa")):
		fmt.Println("load ecdsa key")
		keytype = KEY_ECDSA
		key, err = parseECDSAPublicKey(kb)
	default:
		keytype = KEY_UNSUPPORTED
		err = ErrUnsupportedPublicKey
	}
	return
}

// Load an OpenSSH private key from a file. This is a convenience wrapper
// around LoadPrivateKey, and can fetch the key from an HTTP(S) server,
// as well..
func LoadPrivateKeyFile(name string) (key interface{}, keytype int, err error) {
	kb, err := fetchKey(name, true)
	return LoadPrivateKey(kb)
}

// Load an OpenSSH private key from a byte slice.
func LoadPrivateKey(raw []byte) (key interface{}, keytype int, err error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		err = ErrInvalidPrivateKey
		return
	} else {
		raw := block.Bytes
		if block.Headers != nil && len(block.Headers) != 0 {
			if dekInfo, ok := block.Headers["DEK-Info"]; ok {
				raw, err = decrypt(raw, dekInfo)
				if err != nil {
					return
				}
			}
		}
		ioutil.WriteFile("raw.bin", raw, 0644)
		switch block.Type {
		case "RSA PRIVATE KEY":
			keytype = KEY_RSA
			key, err = x509.ParsePKCS1PrivateKey(raw)
			if err == nil && key.(*rsa.PrivateKey).PublicKey.N.BitLen() < 2047 {
				fmt.Printf("[-] warning: SSH key is a weak key (consider ")
				fmt.Printf("upgrading to a 2048+ bit key.")
			} else if err != nil {
				err = ErrInvalidPrivateKey
			}
		case "EC PRIVATE KEY":
			keytype = KEY_ECDSA
			key, err = x509.ParseECPrivateKey(raw)
			if err != nil {
				err = ErrInvalidPrivateKey
			}
		default:
			err = ErrUnsupportedPrivateKey
			return
		}
	}
	return
}

func parseRSAPublicKey(raw []byte) (key *rsa.PublicKey, err error) {
	buf := bytes.NewBuffer(raw)
	var algorithm, exponent, modulus []byte
	var length int32

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}

	algorithm = make([]byte, length)
	_, err = io.ReadFull(buf, algorithm)
	if err != nil {
		return
	}
	if string(algorithm) != "ssh-rsa" {
		err = ErrInvalidPublicKey
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	exponent = make([]byte, length)
	_, err = io.ReadFull(buf, exponent)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	modulus = make([]byte, length)
	_, err = io.ReadFull(buf, modulus)
	if err != nil {
		return
	}

	key = new(rsa.PublicKey)
	key.N = new(big.Int).SetBytes(modulus)
	key.E = int(new(big.Int).SetBytes(exponent).Int64())
	if key.N.BitLen() < 2047 {
		fmt.Printf("[-] warning: SSH key is a weak key (consider ")
		fmt.Println("upgrading to a 2048+ bit key).")
	}
	return
}

func parseECDSAPublicKey(raw []byte) (key *ecdsa.PublicKey, err error) {
	buf := bytes.NewBuffer(raw)
	var algorithm, curveName, public []byte
	var length int32

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}

	algorithm = make([]byte, length)
	_, err = io.ReadFull(buf, algorithm)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	curveName = make([]byte, length)
	_, err = io.ReadFull(buf, curveName)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	public = make([]byte, length)
	_, err = io.ReadFull(buf, public)
	if err != nil {
		return
	}

	key = new(ecdsa.PublicKey)
	var curve elliptic.Curve
	switch string(curveName) {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		err = ErrUnsupportedPublicKey
		return
	}

		fmt.Println("unmarshal ")
	key.X, key.Y = elliptic.Unmarshal(curve, public)
	if key.X == nil {
		fmt.Println("unmarshal failed")
		err = ErrInvalidPublicKey
		return
	}
	key.Curve = curve
		fmt.Println("unmarshal ok")
	return
}
