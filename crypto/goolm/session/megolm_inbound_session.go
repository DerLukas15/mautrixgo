package session

import (
	"encoding/base64"
	"errors"
	"fmt"

	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/goolm/cipher"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/megolm"
	"maunium.net/go/mautrix/crypto/goolm/message"
	"maunium.net/go/mautrix/crypto/goolm/utilities"
	"maunium.net/go/mautrix/id"
)

const (
	megolmInboundSessionPickleVersionJSON   byte   = 1
	megolmInboundSessionPickleVersionLibOlm uint32 = 2
)

// MegolmInboundSession stores information about the sessions of receive.
type MegolmInboundSession struct {
	Ratchet            megolm.Ratchet          `json:"ratchet"`
	SigningKey         crypto.Ed25519PublicKey `json:"signing_key"`
	InitialRatchet     megolm.Ratchet          `json:"initial_ratchet"`
	SigningKeyVerified bool                    `json:"signing_key_verified"` //not used for now
}

// NewMegolmInboundSession creates a new MegolmInboundSession from a base64 encoded session sharing message.
func NewMegolmInboundSession(input []byte) (*MegolmInboundSession, error) {
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(input)))
	writtenBytes, err := base64.RawStdEncoding.Decode(decoded, input)
	if err != nil {
		return nil, err
	}
	input = decoded[:writtenBytes]
	msg := message.MegolmSessionSharing{}
	err = msg.VerifyAndDecode(input)
	if err != nil {
		return nil, err
	}
	o := &MegolmInboundSession{}
	o.SigningKey = msg.PublicKey
	o.SigningKeyVerified = true
	ratchet, err := megolm.New(msg.Counter, msg.RatchetData)
	if err != nil {
		return nil, err
	}
	o.Ratchet = *ratchet
	o.InitialRatchet = *ratchet
	return o, nil
}

// NewMegolmInboundSessionFromExport creates a new MegolmInboundSession from a base64 encoded session export message.
func NewMegolmInboundSessionFromExport(input []byte) (*MegolmInboundSession, error) {
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(input)))
	writtenBytes, err := base64.RawStdEncoding.Decode(decoded, input)
	if err != nil {
		return nil, err
	}
	input = decoded[:writtenBytes]
	msg := message.MegolmSessionExport{}
	err = msg.Decode(input)
	if err != nil {
		return nil, err
	}
	o := &MegolmInboundSession{}
	o.SigningKey = msg.PublicKey
	ratchet, err := megolm.New(msg.Counter, msg.RatchetData)
	if err != nil {
		return nil, err
	}
	o.Ratchet = *ratchet
	o.InitialRatchet = *ratchet
	return o, nil
}

// MegolmInboundSessionFromPickled loads the MegolmInboundSession details from a pickled base64 string. The input is decrypted with the supplied key.
func MegolmInboundSessionFromPickled(pickled, key []byte) (*MegolmInboundSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("megolmInboundSessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &MegolmInboundSession{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// getRatchet tries to find the correct ratchet for a messageIndex.
func (ms *MegolmInboundSession) getRatchet(messageIndex uint32) (*megolm.Ratchet, error) {
	// pick a megolm instance to use. if we are at or beyond the latest ratchet value, use that
	if (messageIndex - ms.Ratchet.Counter) < uint32(1<<31) {
		ms.Ratchet.AdvanceTo(messageIndex)
		return &ms.Ratchet, nil
	}
	if (messageIndex - ms.InitialRatchet.Counter) >= uint32(1<<31) {
		// the counter is before our initial ratchet - we can't decode this
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrRatchetNotAvailable)
	}
	// otherwise, start from the initial ratchet. Take a copy so that we don't overwrite the initial ratchet
	copiedRatchet := ms.InitialRatchet
	copiedRatchet.AdvanceTo(messageIndex)
	return &copiedRatchet, nil

}

// Decrypt decrypts a base64 encoded group message.
func (ms *MegolmInboundSession) Decrypt(ciphertext []byte) ([]byte, uint32, error) {
	if ms.SigningKey == nil {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrBadMessageFormat)
	}
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(ciphertext)))
	writtenBytes, err := base64.RawStdEncoding.Decode(decoded, ciphertext)
	if err != nil {
		return nil, 0, err
	}
	decoded = decoded[:writtenBytes]
	if err != nil {
		return nil, 0, err
	}
	msg := &message.GroupMessage{}
	err = msg.Decode(decoded)
	if err != nil {
		return nil, 0, err
	}
	if msg.Version != protocolVersion {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrWrongProtocolVersion)
	}
	if msg.Ciphertext == nil || !msg.HasMessageIndex {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrBadMessageFormat)
	}

	// verify signature
	verifiedSignature := msg.VerifySignatureInline(ms.SigningKey, decoded)
	if !verifiedSignature {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrBadSignature)
	}

	targetRatch, err := ms.getRatchet(msg.MessageIndex)
	if err != nil {
		return nil, 0, err
	}

	decrypted, err := targetRatch.Decrypt(decoded, &ms.SigningKey, msg)
	if err != nil {
		return nil, 0, err
	}
	ms.SigningKeyVerified = true
	return decrypted, msg.MessageIndex, nil

}

// SessionID returns the base64 endoded signing key
func (ms *MegolmInboundSession) SessionID() id.SessionID {
	return id.SessionID(base64.RawStdEncoding.EncodeToString(ms.SigningKey))
}

// PickleAsJSON returns an MegolmInboundSession as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (ms *MegolmInboundSession) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(ms, megolmInboundSessionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an MegolmInboundSession by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (ms *MegolmInboundSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(ms, pickled, key, megolmInboundSessionPickleVersionJSON)
}

// SessionExportMessage creates an base64 encoded export of the session.
func (ms *MegolmInboundSession) SessionExportMessage(messageIndex uint32) ([]byte, error) {
	ratchet, err := ms.getRatchet(messageIndex)
	if err != nil {
		return nil, err
	}
	return ratchet.SessionExportMessage(ms.SigningKey)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (o *MegolmInboundSession) Unpickle(pickled, key []byte) error {
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = o.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Session accordingly. It returns the number of bytes read.
func (ms *MegolmInboundSession) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	switch pickledVersion {
	case megolmInboundSessionPickleVersionLibOlm, 1:
	default:
		return 0, fmt.Errorf("unpickle MegolmInboundSession: %w", goolm.ErrBadVersion)
	}
	readBytes, err := ms.InitialRatchet.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = ms.Ratchet.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = ms.SigningKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	if pickledVersion == 1 {
		// pickle v1 had no signing_key_verified field (all keyshares were verified at import time)
		ms.SigningKeyVerified = true
	} else {
		ms.SigningKeyVerified, readBytes, err = libolmpickle.UnpickleBool(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
	}
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled MegolmInboundSession using PickleLibOlm().
func (ms *MegolmInboundSession) Pickle(key []byte) ([]byte, error) {
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
func (ms *MegolmInboundSession) PickleLibOlm(target []byte) (int, error) {
	if len(target) < ms.PickleLen() {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(megolmInboundSessionPickleVersionLibOlm, target)
	writtenInitRatchet, err := ms.InitialRatchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", err)
	}
	written += writtenInitRatchet
	writtenRatchet, err := ms.Ratchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", err)
	}
	written += writtenRatchet
	writtenPubKey, err := ms.SigningKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", err)
	}
	written += writtenPubKey
	written += libolmpickle.PickleBool(ms.SigningKeyVerified, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled session will have.
func (ms *MegolmInboundSession) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(megolmInboundSessionPickleVersionLibOlm)
	length += ms.InitialRatchet.PickleLen()
	length += ms.Ratchet.PickleLen()
	length += ms.SigningKey.PickleLen()
	length += libolmpickle.PickleBoolLen(ms.SigningKeyVerified)
	return length
}
