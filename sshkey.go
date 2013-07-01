/*
	sshkey is a package for loading OpenSSH keys from a file. Currently
	supports RSA and ECDSA keys.
*/
package sshkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"regexp"
	"strings"
)

var (
	ErrInvalidPublicKey      = fmt.Errorf("sshkey: invalid public key")
	ErrInvalidPrivateKey     = fmt.Errorf("sshkey: invalid private key")
	ErrUnsupportedPublicKey  = fmt.Errorf("sshkey: unsupported public key type")
	ErrUnsupportedPrivateKey = fmt.Errorf("sshkey: unsupported private key type")
	ErrInvalidKeySize = fmt.Errorf("sshkey: invalid private key size")
)

type SSHPublicKey struct {
	Type    int // Algorithm for the key
	Key     interface{}
	Comment string
}

func NewPublic(priv interface{}, comment string) *SSHPublicKey {
	pub := new(SSHPublicKey)
	switch priv.(type) {
	case *rsa.PrivateKey:
		rsapub := &priv.(*rsa.PrivateKey).PublicKey
		pub.Type = KEY_RSA
		pub.Key = rsapub
		pub.Comment = comment
	case *ecdsa.PrivateKey:
		ecpub := &priv.(*ecdsa.PrivateKey).PublicKey
		pub.Type = KEY_ECDSA
		pub.Key = ecpub
		pub.Comment = comment
	default:
		return nil
	}

	return pub
}

// These constants are used as the keytype in functions that return a keytype.
const (
	KEY_UNSUPPORTED = -1
	KEY_ECDSA       = iota
	KEY_RSA
)

var pubkeyRegexp = regexp.MustCompile("(?m)^[a-z0-9-]+ (\\S+).*$")
var commentRegexp = regexp.MustCompile("(?m)^[a-z0-9-]+ (\\S+) (\\S*)$")

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
func LoadPublicKeyFile(name string, local bool) (key *SSHPublicKey, err error) {
	kb64, err := fetchKey(name, local)
	return LoadPublicKey(kb64)
}

// LoadPublicKey decodes a byte slice containing an OpenSSH RSA public key
// into an RSA public key.
func LoadPublicKey(raw []byte) (key *SSHPublicKey, err error) {
	kb64 := pubkeyRegexp.ReplaceAll(raw, []byte("$1"))
	kb := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	_, err = base64.StdEncoding.Decode(kb, kb64)
	if err != nil {
		return
	}

	key = new(SSHPublicKey)
	if commentRegexp.Match(raw) {
		key.Comment = string(commentRegexp.ReplaceAll(raw, []byte("$3")))
		key.Comment = strings.TrimSpace(key.Comment)
	}

	switch {
	case bytes.HasPrefix(raw, []byte("ssh-rsa")):
		key.Type = KEY_RSA
		key.Key, err = parseRSAPublicKey(kb)
	case bytes.HasPrefix(raw, []byte("ecdsa")):
		key.Type = KEY_ECDSA
		key.Key, err = parseECDSAPublicKey(kb)
	default:
		key.Type = KEY_UNSUPPORTED
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

	key.X, key.Y = elliptic.Unmarshal(curve, public)
	if key.X == nil {
		err = ErrInvalidPublicKey
		return
	}
	key.Curve = curve
	return
}

func uint32ToBlob(n uint32) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, n)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func curveName(curve elliptic.Curve) []byte {
	switch curve {
	case elliptic.P256():
		return []byte("nistp256")
	case elliptic.P384():
		return []byte("nistp384")
	case elliptic.P521():
		return []byte("nistp521")
	default:
		return nil
	}
}

func publicToBlob(pub *SSHPublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)

	switch pub.Key.(type) {
	case *rsa.PublicKey:
		rsapub := pub.Key.(*rsa.PublicKey)
		tag1 := uint32ToBlob(7) // 7 characters for 'ssh-rsa'
		if tag1 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag1)
		buf.Write([]byte("ssh-rsa"))

		E := big.NewInt(int64(rsapub.E)).Bytes()
		tag2 := uint32ToBlob(uint32(len(E)))
		if tag2 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag2)
		buf.Write(E)

		N := rsapub.N.Bytes()
		tag3 := uint32ToBlob(uint32(len(N) + 1))
		if tag3 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag3)
		buf.Write([]byte{0})
		buf.Write(N)
	case *ecdsa.PublicKey:
		ecpub := pub.Key.(*ecdsa.PublicKey)
		cname := curveName(ecpub.Curve)
		if cname == nil {
			return nil, ErrInvalidPublicKey
		}
		algo := []byte(fmt.Sprintf("ecdsa-sha2-%s", string(cname)))
		tag1 := uint32ToBlob(uint32(len(algo)))
		if tag1 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag1)
		buf.Write(algo)

		tag2 := uint32ToBlob(uint32(len(cname)))
		if tag2 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag2)
		buf.Write(cname)

		pubkey := elliptic.Marshal(ecpub.Curve, ecpub.X, ecpub.Y)
		if pubkey == nil {
			return nil, ErrInvalidPublicKey
		}
		tag3 := uint32ToBlob(uint32(len(pubkey)))
		if tag3 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag3)
		buf.Write(pubkey)
	default:
		return nil, ErrInvalidPublicKey
	}

	return buf.Bytes(), nil
}

func MarshalPrivate(priv interface{}, password string) (out []byte, err error) {
	var (
		keytype int
		der     []byte
		btype   string
	)

	switch priv.(type) {
	case *rsa.PrivateKey:
		keytype = KEY_RSA
		der = x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
		if der == nil {
			err = ErrInvalidPrivateKey
			return
		}
		btype = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		keytype = KEY_ECDSA
		der, err = marshalECDSAKey(priv.(*ecdsa.PrivateKey))
		btype = "EC PRIVATE KEY"
	default:
		err = ErrInvalidPrivateKey
		return
	}

	if password != "" {
		out, err = encrypt(der, keytype, password)
		return
	}
	var block pem.Block
	block.Type = btype
	block.Bytes = der
	out = pem.EncodeToMemory(&block)
	return
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func marshalECDSAKey(priv *ecdsa.PrivateKey) (out []byte, err error) {
	var eckey ecPrivateKey

	eckey.Version = 1
	eckey.PrivateKey = priv.D.Bytes()
	switch priv.PublicKey.Curve {
	case elliptic.P256():
		eckey.NamedCurveOID = oidNamedCurveP256
	case elliptic.P384():
		eckey.NamedCurveOID = oidNamedCurveP384
	case elliptic.P521():
		eckey.NamedCurveOID = oidNamedCurveP521
	default:
		err = ErrInvalidPrivateKey
	}

	pkey := elliptic.Marshal(priv.PublicKey.Curve, priv.PublicKey.X,
		priv.PublicKey.Y)
	if pkey == nil {
		err = ErrInvalidPrivateKey
		return
	}

	eckey.PublicKey = asn1.BitString{
		BitLength: len(pkey) * 8,
		Bytes:     pkey,
	}
	out, err = asn1.Marshal(eckey)
	return
}

func MarshalPublic(pub *SSHPublicKey) (out []byte) {
	blob, err := publicToBlob(pub)
	if err != nil {
		return nil
	}
	encodedBlob := base64.StdEncoding.EncodeToString(blob)

	var algo string

	switch pub.Type {
	case KEY_RSA:
		algo = "ssh-rsa"
	case KEY_ECDSA:
		algo = fmt.Sprintf("ecdsa-sha2-%s",
			curveName(pub.Key.(*ecdsa.PublicKey).Curve))
	default:
		return nil
	}

	out = []byte(fmt.Sprintf("%s %s %s", algo, encodedBlob, pub.Comment))
	return
}

func (key *SSHPublicKey) Size() int {
	switch key.Type {
	case KEY_RSA:
		return key.Key.(*rsa.PublicKey).N.BitLen()
	case KEY_ECDSA:
		return key.Key.(*ecdsa.PublicKey).Curve.Params().BitSize
	default:
		return 0
	}
}

func GenerateSSHKey(keytype, size int) (key interface{}, err error) {
	switch keytype {
	case KEY_RSA:
		if size < 2048 {
			return nil, ErrInvalidKeySize
		}
		var rsakey *rsa.PrivateKey
		rsakey, err = rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return
		}
		key = rsakey
	case KEY_ECDSA:
		var eckey *ecdsa.PrivateKey
		switch size {
		case 256:
			eckey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			eckey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			eckey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, ErrInvalidKeySize
		}
		key = eckey
	}

	return
}
