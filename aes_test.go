package crypto

import (
	"fmt"
	"testing"
)

func Test_AES(t *testing.T) {
	aes := Default()

	var txt2encrypt = "santosh-gupta"
	fmt.Printf("Text: %s\n", txt2encrypt)

	enc, err := aes.Encrypt(txt2encrypt)
	if err != nil {
		t.Errorf("Encrypt failed. %v", err)
	}
	fmt.Printf("Enc: %s\n", enc)

	dec, err := aes.Decrypt(enc)
	if err != nil {
		t.Errorf("Decrypt failed. %v", err)
	}
	fmt.Printf("Dec: %s\n", dec)
}

func Test_AES2(t *testing.T) {
	aes := Default()

	var txt2encrypt = "santosh-gupta"
	fmt.Printf("Text: %s\n", txt2encrypt)

	enc, err := aes.Encrypt(txt2encrypt)
	if err != nil {
		t.Errorf("Encrypt failed. %v", err)
	}
	fmt.Printf("Enc: %s\n", enc)

	var s struct {
		Name string
		Pwd  string
	}
	s.Name = txt2encrypt
	s.Pwd, err = aes.Encrypt(s.Name)
	fmt.Printf("Pwd: %s\n", s.Pwd)

}

func Test_AES3(t *testing.T) {
	aes := Default()

	dec, err := aes.Decrypt("wrc2S0J4JtXI6uK6jirZp1U+DYds4nz2uvIv4cEhDdg=")
	if err != nil {
		t.Errorf("Decrypt failed. %v", err)
	}
	fmt.Printf("Dec: %s\n", dec)
}

func Test_AES4(t *testing.T) {
	aes := Init(
		[]byte{101, 217, 19, 11, 196, 29, 24, 26, 19, 218, 131, 240, 161, 85, 45, 114, 124, 27, 162, 36, 112, 222, 209, 241, 24, 175, 144, 171, 43, 236, 53, 217},
		[]byte{111, 94, 191, 141, 215, 150, 103, 119, 237, 121, 22, 118, 55, 32, 114, 186})

	var txt2encrypt = "santosh-gupta"
	fmt.Printf("Text: %s\n", txt2encrypt)

	enc, err := aes.Encrypt(txt2encrypt)
	if err != nil {
		t.Errorf("Encrypt failed. %v", err)
	}
	fmt.Printf("Enc: %s\n", enc)

	var s struct {
		Name string
		Pwd  string
	}
	s.Name = txt2encrypt
	s.Pwd, err = aes.Encrypt(s.Name)
	fmt.Printf("Pwd: %s\n", s.Pwd)

}

func Test_EncWithPass(t *testing.T) {

	var txt2encrypt = "santosh-gupta"
	fmt.Printf("Text: %s\n", txt2encrypt)

	enc := EncryptWithPassphrase(txt2encrypt, "9415423284")
	fmt.Printf("Enc: %s\n", enc)

	dec := DecryptWithPassphrase(enc, "9415423284")
	if txt2encrypt != dec {
		fmt.Printf("before and adter string do not match")
		t.Fail()
	}
}
