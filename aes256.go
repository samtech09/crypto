// aes256.go
// This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
//
// This is an implementation of the AES algorithm, specifically CBC mode,
// with 256 bits key length and PKCS7 padding.
//
// Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
// Licensed under the MIT license
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	b64 "encoding/base64"
)

var salt = []byte{21, 38, 57, 106, 39, 75, 82, 94}

// // Encrypts text with the passphrase using CBC mode
// func EncryptWithPassphrase(text string, passphrase string) string {
// 	salt := make([]byte, 8)
// 	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
// 		panic(err.Error())
// 	}

// 	key, iv := __DeriveKeyAndIv(passphrase, string(salt))

// 	block, err := aes.NewCipher([]byte(key))
// 	if err != nil {
// 		panic(err)
// 	}

// 	pad := __PKCS5Padding([]byte(text), block.BlockSize())
// 	ecb := cipher.NewCBCEncrypter(block, []byte(iv))
// 	encrypted := make([]byte, len(pad))
// 	ecb.CryptBlocks(encrypted, pad)

// 	return b64.StdEncoding.EncodeToString([]byte("Salted__" + string(salt) + string(encrypted)))
// }

// // Decrypts encrypted text with the passphrase using CBC mode
// func DecryptWithPassphrace(encrypted string, passphrase string) string {
// 	ct, _ := b64.StdEncoding.DecodeString(encrypted)
// 	if len(ct) < 16 || string(ct[:8]) != "Salted__" {
// 		return ""
// 	}

// 	salt := ct[8:16]
// 	ct = ct[16:]
// 	key, iv := __DeriveKeyAndIv(passphrase, string(salt))

// 	block, err := aes.NewCipher([]byte(key))
// 	if err != nil {
// 		panic(err)
// 	}

// 	//cbc := cipher.NewCBCDecrypter(block, []byte(iv))
// 	cbc := cipher.NewCBCDecrypter(block, []byte(iv))
// 	dst := make([]byte, len(ct))
// 	cbc.CryptBlocks(dst, ct)

// 	return string(__PKCS5Trimming(dst))
// }

// EncryptWithPassphrase text with the passphrase using CFB mode
func EncryptWithPassphrase(text string, passphrase string) string {
	//salt := make([]byte, 8)
	//if _, err := io.ReadFull(rand.Reader, salt); err != nil {
	//	panic(err.Error())
	//}

	key, iv := __DeriveKeyAndIv(passphrase, string(salt))

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	pad := __PKCS5Padding([]byte(text), block.BlockSize())
	cfb := cipher.NewCFBEncrypter(block, []byte(iv))
	encrypted := make([]byte, len(pad))
	cfb.XORKeyStream(encrypted, pad)

	//return b64.StdEncoding.EncodeToString([]byte("Salted__" + string(salt) + string(encrypted)))
	return b64.StdEncoding.EncodeToString(encrypted)
}

// DecryptWithPassphrace encrypted text with the passphrase using CFB mode
func DecryptWithPassphrase(encrypted string, passphrase string) string {
	ct, _ := b64.StdEncoding.DecodeString(encrypted)
	//if len(ct) < 16 || string(ct[:8]) != "Salted__" {
	//	return ""
	//}
	if len(ct) < 16 {
		return ""
	}

	//salt := ct[8:16]
	//ct = ct[16:]
	key, iv := __DeriveKeyAndIv(passphrase, string(salt))

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	//cfb := cipher.NewCBCDecrypter(block, []byte(iv))
	cfb := cipher.NewCFBDecrypter(block, []byte(iv))
	dst := make([]byte, len(ct))
	cfb.XORKeyStream(dst, ct)

	return string(__PKCS5Trimming(dst))
}

func __PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func __PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func __DeriveKeyAndIv(passphrase string, salt string) (string, string) {
	salted := ""
	dI := ""

	for len(salted) < 48 {
		md := md5.New()
		md.Write([]byte(dI + passphrase + salt))
		dM := md.Sum(nil)
		dI = string(dM[:16])
		salted = salted + dI
	}

	key := salted[0:32]
	iv := salted[32:48]

	return key, iv
}
