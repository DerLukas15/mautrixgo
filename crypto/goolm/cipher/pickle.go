package cipher

import (
	"encoding/base64"
	"fmt"

	"maunium.net/go/mautrix/crypto/goolm"
)

const (
	kdfPickle       = "Pickle" //used to derive the keys for encryption
	pickleMACLength = 8
)

// PickleBlockSize returns the blocksize of the used cipher.
func PickleBlockSize() int {
	return AESSha512BlockSize()
}

// Pickle encrypts the input with the key and the cipher AESSHA256. The result is then encoded in base64.
func Pickle(key, input []byte) ([]byte, error) {
	pickleCipher := NewAESSHA256([]byte(kdfPickle))
	ciphertext, err := pickleCipher.Encrypt(key, input)
	if err != nil {
		return nil, err
	}
	mac, err := pickleCipher.MAC(key, ciphertext)
	if err != nil {
		return nil, err
	}
	ciphertext = append(ciphertext, mac[:pickleMACLength]...)
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(ciphertext)))
	base64.RawStdEncoding.Encode(encoded, ciphertext)
	return encoded, nil
}

// Unpickle decodes the input from base64 and decrypts the decoded input with the key and the cipher AESSHA256.
func Unpickle(key, input []byte) ([]byte, error) {
	pickleCipher := NewAESSHA256([]byte(kdfPickle))
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(input)))
	writtenBytes, err := base64.RawStdEncoding.Decode(decoded, input)
	if err != nil {
		return nil, err
	}
	ciphertext := decoded[:writtenBytes]
	if err != nil {
		return nil, err
	}
	//remove mac and check
	verified, err := pickleCipher.Verify(key, ciphertext[:len(ciphertext)-pickleMACLength], ciphertext[len(ciphertext)-pickleMACLength:])
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("decrypt pickle: %w", goolm.ErrBadMAC)
	}
	//Set to next block size
	targetCipherText := make([]byte, int(len(ciphertext)/PickleBlockSize())*PickleBlockSize())
	copy(targetCipherText, ciphertext)
	plaintext, err := pickleCipher.Decrypt(key, targetCipherText)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
