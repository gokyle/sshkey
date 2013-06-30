package sshkey

// Functions for handling password protected keys.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

var PasswordPrompt func(prompt string) (password string, err error) = DefaultPasswordPrompt

var (
	ErrInvalidDEK      = fmt.Errorf("sshkey: invalid DEK info")
	ErrUnableToDecrypt = fmt.Errorf("sshkey: unable to decrypt key")
)

func decrypt(raw []byte, dekInfo string) (key []byte, err error) {
	dekInfoMap := strings.Split(dekInfo, ",")
	if len(dekInfoMap) != 2 {
		return nil, ErrInvalidDEK
	}
	algo := dekInfoMap[0]
	iv, err := hex.DecodeString(dekInfoMap[1])
	if err != nil {
		return
	}

	password, err := PasswordPrompt("SSH key password: ")
	if err != nil {
		return
	}
	aeskey, err := opensshKDF(iv, []byte(password))
	if err != nil {
		return
	}

	switch algo {
	case "AES-128-CBC":
		key, err = aesCBCdecrypt(aeskey, iv, raw)
	default:
		err = ErrUnableToDecrypt
	}
	return
}

func opensshKDF(iv []byte, password []byte) (key []byte, err error) {
	hash := md5.New()
	hash.Write(password)
	hash.Write(iv[:8])
	key = hash.Sum(nil)
	return
}

func DefaultPasswordPrompt(prompt string) (password string, err error) {
	fmt.Printf(prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	password = strings.TrimSpace(line)
	return
}

func aesCBCdecrypt(aeskey, iv, ct []byte) (key []byte, err error) {
	c, err := aes.NewCipher(aeskey)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCDecrypter(c, iv)
	key = make([]byte, len(ct))
	cbc.CryptBlocks(key, ct)
	key = sshUnpad(key)
	return
}

// seriously!?
func sshUnpad(padded []byte) (unpadded []byte) {
	paddedLen := len(padded)
	var padnum int = int(padded[paddedLen-1])
	stop := len(padded) - padnum
	return padded[:stop]
}
