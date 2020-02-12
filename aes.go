package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

//AES object
type AES struct {
	Key    []byte
	Vector []byte
}

//Default return AES struct with default values
func Default() *AES {
	return &AES{
        Key:    []byte{100, 100, 100, 100, 100, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 100, 100, 100, 100, 100, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111},
		Vector: []byte{99, 99, 99, 99, 99, 99, 99, 99, 88, 88, 88, 88, 88, 88, 88, 88},
	}
}

//Init return AES object with custom Key and Vector
func Init(bKey, bVector []byte) *AES {
	return &AES{
		bKey,
		bVector,
	}
}

//Encrypt cipher given text using AES-CFB algorithm
func (a *AES) Encrypt(textToEncrypt string) (string, error) {
	encrypted := make([]byte, len(textToEncrypt))
	encrypted, err := a.encryptAESCFB([]byte(textToEncrypt))
	if err != nil {
		return "", err
	}
	//fmt.Printf("\n\n%v\n", encrypted)
	return encodeBase64(encrypted), nil
}

//Decrypt decipher given text using AES-CFB algorithm
func (a *AES) Decrypt(textToDecrypt string) (string, error) {
	decrypted, err := a.decryptAESCFB(decodeBase64(textToDecrypt))
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func (a *AES) encryptAESCFB(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	//fmt.Printf("Block Size: %d\n", bs)

	if len(src)%bs != 0 {
		//src = padSlice(src, bs)
		src, _ = pkcs7Pad(src, bs)
	}

	dst := make([]byte, len(src))
	aesEncrypter := cipher.NewCFBEncrypter(block, a.Vector)
	aesEncrypter.XORKeyStream(dst, src)

	//fmt.Printf("AES-CFB Enc: %s\n", encodeBase64(dst))
	//fmt.Printf("\n\n%v\n", dst)
	return dst, nil
}

func (a *AES) decryptAESCFB(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()

	if len(src)%bs != 0 {
		//src = padSlice(src, bs)
		src, _ = pkcs7Pad(src, bs)
	}

	dst := make([]byte, len(src))
	aesDecrypter := cipher.NewCFBDecrypter(block, a.Vector)
	aesDecrypter.XORKeyStream(dst, src)
	//fmt.Printf("AES-CFB Dec: %s\n", dst)
	return dst, nil
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// pad slice with zero bytes
func zeroPad(src []byte, blocklen int) []byte {
	// src must be a multiple of block size
	mult := int((len(src) / blocklen) + 1)
	leng := blocklen * mult

	//fmt.Printf("Mult: %d, leng: %d\n", mult, leng)

	src_padded := make([]byte, leng)
	copy(src_padded, src)
	return src_padded
}

// Appends padding with PKCS7
// appended bytes has total count of bytes appended
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}
