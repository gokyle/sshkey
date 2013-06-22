/*
	sshkey is a package for loading OpenSSH RSA keys from a file.
*/
package sshkey

import (
	"bytes"
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
	ErrInvalidPublicKey  = fmt.Errorf("invalid public key")
	ErrInvalidPrivateKey = fmt.Errorf("invalid private key")
)

var pubkeyRegexp = regexp.MustCompile("(?m)^ssh-... (\\S+).*$")

type sshPublicKey struct {
	Algorithm []byte
	Modulus   []byte
	Exponent  []byte
}

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

// LoadPublicKey loads an OpenSSH RSA public key from a file or via HTTP. If
// local is false, the key will be fetched over HTTP.
func LoadPublicKeyFile(name string, local bool) (key *rsa.PublicKey, err error) {
	kb64, err := fetchKey(name, local)
	return LoadPublicKey(kb64)
}

// LoadPublicKey decodes a byte slice containing an OpenSSH RSA public key
// into an RSA public key.
func LoadPublicKey(raw []byte) (key *rsa.PublicKey, err error) {
	raw = pubkeyRegexp.ReplaceAll(raw, []byte("$1"))
	kb := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	_, err = base64.StdEncoding.Decode(kb, raw)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(kb)
	var pubKey sshPublicKey
	var length int32

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}

	pubKey.Algorithm = make([]byte, length)
	_, err = io.ReadFull(buf, pubKey.Algorithm)
	if err != nil {
		return
	}
	if string(pubKey.Algorithm) != "ssh-rsa" {
		err = ErrInvalidPublicKey
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	pubKey.Exponent = make([]byte, length)
	_, err = io.ReadFull(buf, pubKey.Exponent)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	pubKey.Modulus = make([]byte, length)
	_, err = io.ReadFull(buf, pubKey.Modulus)
	if err != nil {
		return
	}

	key = new(rsa.PublicKey)
	key.N = new(big.Int).SetBytes(pubKey.Modulus)
	key.E = int(new(big.Int).SetBytes(pubKey.Exponent).Int64())
	if key.N.BitLen() < 2047 {
		fmt.Printf("[-] warning: SSH key is a weak key (consider ")
		fmt.Println("upgrading to a 2048+ bit key).")
	}
	return
}

// Load an OpenSSH RSA private key from a file.
func LoadPrivateKeyFile(name string) (key *rsa.PrivateKey, err error) {
	kb, err := fetchKey(name, true)
	return LoadPrivateKey(kb)
}

// Load an OpenSSH RSA private key from a byte slice.
func LoadPrivateKey(raw []byte) (key *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		err = ErrInvalidPrivateKey
		return
	} else if block.Type != "RSA PRIVATE KEY" {
		err = ErrInvalidPrivateKey
		return
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil && key.PublicKey.N.BitLen() < 2047 {
		fmt.Printf("[-] warning: SSH key is a weak key (consider ")
		fmt.Printf("upgrading to a 2048+ bit key.")
	}
	return
}
