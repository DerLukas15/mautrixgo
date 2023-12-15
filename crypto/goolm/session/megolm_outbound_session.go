package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"

	"maunium.net/go/mautrix/id"

	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/goolm/cipher"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/megolm"
	"maunium.net/go/mautrix/crypto/goolm/utilities"
)

const (
	megolmOutboundSessionPickleVersion       byte   = 1
	megolmOutboundSessionPickleVersionLibOlm uint32 = 1
)

// MegolmOutboundSession stores information about the sessions to send.
type MegolmOutboundSession struct {
	Ratchet    megolm.Ratchet        `json:"ratchet"`
	SigningKey crypto.Ed25519KeyPair `json:"signing_key"`
}

// NewMegolmOutboundSession creates a new MegolmOutboundSession.
func NewMegolmOutboundSession() (*MegolmOutboundSession, error) {
	o := &MegolmOutboundSession{}
	var err error
	o.SigningKey, err = crypto.Ed25519GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	var randomData [megolm.RatchetParts * megolm.RatchetPartLength]byte
	_, err = rand.Read(randomData[:])
	if err != nil {
		return nil, err
	}
	ratchet, err := megolm.New(0, randomData)
	if err != nil {
		return nil, err
	}
	o.Ratchet = *ratchet
	return o, nil
}

// MegolmOutboundSessionFromPickled loads the MegolmOutboundSession details from a pickled base64 string. The input is decrypted with the supplied key.
func MegolmOutboundSessionFromPickled(pickled, key []byte) (*MegolmOutboundSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("megolmOutboundSessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &MegolmOutboundSession{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Encrypt encrypts the plaintext as a base64 encoded group message.
func (ms *MegolmOutboundSession) Encrypt(plaintext []byte) ([]byte, error) {
	encrypted, err := ms.Ratchet.Encrypt(plaintext, &ms.SigningKey)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(encrypted)))
	base64.RawStdEncoding.Encode(encoded, encrypted)
	return encoded, nil
}

// SessionID returns the base64 endoded public signing key
func (ms *MegolmOutboundSession) SessionID() id.SessionID {
	return id.SessionID(base64.RawStdEncoding.EncodeToString(ms.SigningKey.PublicKey))
}

// PickleAsJSON returns an Session as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (ms *MegolmOutboundSession) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(ms, megolmOutboundSessionPickleVersion, key)
}

// UnpickleAsJSON updates an Session by a base64 encrypted string with the key. The unencrypted representation has to be in JSON format.
func (ms *MegolmOutboundSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(ms, pickled, key, megolmOutboundSessionPickleVersion)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (ms *MegolmOutboundSession) Unpickle(pickled, key []byte) error {
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = ms.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Session accordingly. It returns the number of bytes read.
func (ms *MegolmOutboundSession) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	switch pickledVersion {
	case megolmOutboundSessionPickleVersionLibOlm:
	default:
		return 0, fmt.Errorf("unpickle MegolmInboundSession: %w", goolm.ErrBadVersion)
	}
	readBytes, err := ms.Ratchet.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = ms.SigningKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled MegolmOutboundSession using PickleLibOlm().
func (ms *MegolmOutboundSession) Pickle(key []byte) ([]byte, error) {
	pickeledBytes := make([]byte, ms.PickleLen())
	written, err := ms.PickleLibOlm(pickeledBytes)
	if err != nil {
		return nil, err
	}
	if written != len(pickeledBytes) {
		return nil, errors.New("number of written bytes not correct")
	}
	encrypted, err := cipher.Pickle(key, pickeledBytes)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// PickleLibOlm encodes the session into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (ms *MegolmOutboundSession) PickleLibOlm(target []byte) (int, error) {
	if len(target) < ms.PickleLen() {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(megolmOutboundSessionPickleVersionLibOlm, target)
	writtenRatchet, err := ms.Ratchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenPubKey, err := ms.SigningKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenPubKey
	return written, nil
}

// PickleLen returns the number of bytes the pickled session will have.
func (ms *MegolmOutboundSession) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(megolmOutboundSessionPickleVersionLibOlm)
	length += ms.Ratchet.PickleLen()
	length += ms.SigningKey.PickleLen()
	return length
}

func (ms *MegolmOutboundSession) SessionSharingMessage() ([]byte, error) {
	return ms.Ratchet.SessionSharingMessage(ms.SigningKey)
}
