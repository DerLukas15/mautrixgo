package session

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/goolm/cipher"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/message"
	"maunium.net/go/mautrix/crypto/goolm/olm"
	"maunium.net/go/mautrix/crypto/goolm/utilities"
	"maunium.net/go/mautrix/id"
)

const (
	olmSessionPickleVersionJSON   uint8  = 1
	olmSessionPickleVersionLibOlm uint32 = 1
)

const (
	protocolVersion = 0x3
)

// OlmSession stores all information for an olm session
type OlmSession struct {
	ReceivedMessage  bool                       `json:"received_message"`
	AliceIdentityKey crypto.Curve25519PublicKey `json:"alice_id_key"`
	AliceBaseKey     crypto.Curve25519PublicKey `json:"alice_base_key"`
	BobOneTimeKey    crypto.Curve25519PublicKey `json:"bob_one_time_key"`
	Ratchet          olm.Ratchet                `json:"ratchet"`
}

// SearchOTKFunc is used to retrieve a crypto.OneTimeKey from a public key.
type SearchOTKFunc = func(crypto.Curve25519PublicKey) *crypto.OneTimeKey

// OlmSessionFromJSONPickled loads an OlmSession from a pickled base64 string. Decrypts
// the Session using the supplied key.
func OlmSessionFromJSONPickled(pickled, key []byte) (*OlmSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("sessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &OlmSession{}
	err := a.UnpickleAsJSON(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// OlmSessionFromPickled loads the OlmSession details from a pickled base64 string. The input is decrypted with the supplied key.
func OlmSessionFromPickled(pickled, key []byte) (*OlmSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("sessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &OlmSession{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// NewOlmSession creates a new Session.
func NewOlmSession() *OlmSession {
	s := &OlmSession{}
	s.Ratchet = *olm.New()
	return s
}

// NewOutboundOlmSession creates a new outbound session for sending the first message to a
// given curve25519 identityKey and oneTimeKey.
func NewOutboundOlmSession(identityKeyAlice crypto.Curve25519KeyPair, identityKeyBob crypto.Curve25519PublicKey, oneTimeKeyBob crypto.Curve25519PublicKey) (*OlmSession, error) {
	s := NewOlmSession()
	//generate E_A
	baseKey, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	//generate T_0
	ratchetKey, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	//Calculate shared secret via Triple Diffie-Hellman
	var secret []byte
	//ECDH(I_A,E_B)
	idSecret, err := identityKeyAlice.SharedSecret(oneTimeKeyBob)
	if err != nil {
		return nil, err
	}
	//ECDH(E_A,I_B)
	baseIdSecret, err := baseKey.SharedSecret(identityKeyBob)
	if err != nil {
		return nil, err
	}
	//ECDH(E_A,E_B)
	baseOneTimeSecret, err := baseKey.SharedSecret(oneTimeKeyBob)
	if err != nil {
		return nil, err
	}
	secret = append(secret, idSecret...)
	secret = append(secret, baseIdSecret...)
	secret = append(secret, baseOneTimeSecret...)
	//Init Ratchet
	s.Ratchet.InitializeAsAlice(secret, ratchetKey)
	s.AliceIdentityKey = identityKeyAlice.PublicKey
	s.AliceBaseKey = baseKey.PublicKey
	s.BobOneTimeKey = oneTimeKeyBob
	return s, nil
}

// NewInboundOlmSession creates a new inbound session from receiving the first message.
func NewInboundOlmSession(identityKeyAlice *crypto.Curve25519PublicKey, receivedOTKMsg []byte, searchBobOTK SearchOTKFunc, identityKeyBob crypto.Curve25519KeyPair) (*OlmSession, error) {
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(receivedOTKMsg)))
	writtenBytes, err := base64.RawStdEncoding.Decode(decoded, receivedOTKMsg)
	if err != nil {
		return nil, err
	}
	decodedOTKMsg := decoded[:writtenBytes]
	s := NewOlmSession()

	//decode OneTimeKeyMessage
	oneTimeMsg := message.PreKeyMessage{}
	err = oneTimeMsg.Decode(decodedOTKMsg)
	if err != nil {
		return nil, fmt.Errorf("OneTimeKeyMessage decode: %w", err)
	}
	if !oneTimeMsg.CheckFields(identityKeyAlice) {
		return nil, fmt.Errorf("OneTimeKeyMessage check fields: %w", goolm.ErrBadMessageFormat)
	}

	//Either the identityKeyAlice is set and/or the oneTimeMsg.IdentityKey is set, which is checked
	// by oneTimeMsg.CheckFields
	if identityKeyAlice != nil && len(oneTimeMsg.IdentityKey) != 0 {
		//if both are set, compare them
		if !identityKeyAlice.Equal(oneTimeMsg.IdentityKey) {
			return nil, fmt.Errorf("OneTimeKeyMessage identity keys: %w", goolm.ErrBadMessageKeyID)
		}
	}
	if identityKeyAlice == nil {
		//for downstream use set
		identityKeyAlice = &oneTimeMsg.IdentityKey
	}

	oneTimeKeyBob := searchBobOTK(oneTimeMsg.OneTimeKey)
	if oneTimeKeyBob == nil {
		return nil, fmt.Errorf("ourOneTimeKey: %w", goolm.ErrBadMessageKeyID)
	}

	//Calculate shared secret via Triple Diffie-Hellman
	var secret []byte
	//ECDH(E_B,I_A)
	idSecret, err := oneTimeKeyBob.Key.SharedSecret(*identityKeyAlice)
	if err != nil {
		return nil, err
	}
	//ECDH(I_B,E_A)
	baseIdSecret, err := identityKeyBob.SharedSecret(oneTimeMsg.BaseKey)
	if err != nil {
		return nil, err
	}
	//ECDH(E_B,E_A)
	baseOneTimeSecret, err := oneTimeKeyBob.Key.SharedSecret(oneTimeMsg.BaseKey)
	if err != nil {
		return nil, err
	}
	secret = append(secret, idSecret...)
	secret = append(secret, baseIdSecret...)
	secret = append(secret, baseOneTimeSecret...)
	//decode message
	msg := message.Message{}
	err = msg.Decode(oneTimeMsg.Message)
	if err != nil {
		return nil, fmt.Errorf("message decode: %w", err)
	}

	if len(msg.RatchetKey) == 0 {
		return nil, fmt.Errorf("message missing ratchet key: %w", goolm.ErrBadMessageFormat)
	}
	//Init Ratchet
	s.Ratchet.InitializeAsBob(secret, msg.RatchetKey)
	s.AliceBaseKey = oneTimeMsg.BaseKey
	s.AliceIdentityKey = oneTimeMsg.IdentityKey
	s.BobOneTimeKey = oneTimeKeyBob.Key.PublicKey

	//https://gitlab.matrix.org/matrix-org/olm/blob/master/docs/olm.md states to remove the oneTimeKey
	//this is done via the account itself
	return s, nil
}

// PickleAsJSON returns an Session as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (os *OlmSession) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(os, olmSessionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Session by a base64 encrypted string with the key. The unencrypted representation has to be in JSON format.
func (os *OlmSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(os, pickled, key, olmSessionPickleVersionJSON)
}

// ID returns an identifier for this Session.  Will be the same for both ends of the conversation.
// Generated by hashing the public keys used to create the session.
func (os *OlmSession) ID() id.SessionID {
	message := make([]byte, 3*crypto.Curve25519KeyLength)
	copy(message, os.AliceIdentityKey)
	copy(message[crypto.Curve25519KeyLength:], os.AliceBaseKey)
	copy(message[2*crypto.Curve25519KeyLength:], os.BobOneTimeKey)
	hash := crypto.SHA256(message)
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(hash)))
	base64.RawStdEncoding.Encode(encoded, hash)
	return id.SessionID(encoded)
}

// HasReceivedMessage returns true if this session has received any message.
func (os *OlmSession) HasReceivedMessage() bool {
	return os.ReceivedMessage
}

// MatchesInboundSessionFrom checks if the oneTimeKeyMsg message is set for this inbound
// Session.  This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply.  Returns true if the session
// matches.  Returns false if the session does not match.
func (os *OlmSession) MatchesInboundSessionFrom(theirIdentityKeyEncoded *id.Curve25519, receivedOTKMsg []byte) (bool, error) {
	if len(receivedOTKMsg) == 0 {
		return false, fmt.Errorf("inbound match: %w", goolm.ErrEmptyInput)
	}
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(receivedOTKMsg)))
	writtenBytes, err := base64.RawStdEncoding.Decode(decoded, receivedOTKMsg)
	if err != nil {
		return false, err
	}
	decodedOTKMsg := decoded[:writtenBytes]

	var theirIdentityKey *crypto.Curve25519PublicKey
	if theirIdentityKeyEncoded != nil {
		decodedKey, err := base64.RawStdEncoding.DecodeString(string(*theirIdentityKeyEncoded))
		if err != nil {
			return false, err
		}
		theirIdentityKeyByte := crypto.Curve25519PublicKey(decodedKey)
		theirIdentityKey = &theirIdentityKeyByte
	}

	msg := message.PreKeyMessage{}
	err = msg.Decode(decodedOTKMsg)
	if err != nil {
		return false, err
	}
	if !msg.CheckFields(theirIdentityKey) {
		return false, nil
	}

	same := true
	if msg.IdentityKey != nil {
		same = same && msg.IdentityKey.Equal(os.AliceIdentityKey)
	}
	if theirIdentityKey != nil {
		same = same && theirIdentityKey.Equal(os.AliceIdentityKey)
	}
	same = same && bytes.Equal(msg.BaseKey, os.AliceBaseKey)
	same = same && bytes.Equal(msg.OneTimeKey, os.BobOneTimeKey)
	return same, nil
}

// EncryptMsgType returns the type of the next message that Encrypt will
// return. Returns MsgTypePreKey if the message will be a oneTimeKeyMsg.
// Returns MsgTypeMsg if the message will be a normal message.
func (os *OlmSession) EncryptMsgType() id.OlmMsgType {
	if os.ReceivedMessage {
		return id.OlmMsgTypeMsg
	}
	return id.OlmMsgTypePreKey
}

// Encrypt encrypts a message using the Session. Returns the encrypted message base64 encoded.  If reader is nil, crypto/rand is used for key generations.
func (os *OlmSession) Encrypt(plaintext []byte, reader io.Reader) (id.OlmMsgType, []byte, error) {
	if len(plaintext) == 0 {
		return 0, nil, fmt.Errorf("encrypt: %w", goolm.ErrEmptyInput)
	}
	messageType := os.EncryptMsgType()
	encrypted, err := os.Ratchet.Encrypt(plaintext, reader)
	if err != nil {
		return 0, nil, err
	}
	result := encrypted
	if !os.ReceivedMessage {
		msg := message.PreKeyMessage{}
		msg.Version = protocolVersion
		msg.OneTimeKey = os.BobOneTimeKey
		msg.IdentityKey = os.AliceIdentityKey
		msg.BaseKey = os.AliceBaseKey
		msg.Message = encrypted

		var err error
		messageBody, err := msg.Encode()
		if err != nil {
			return 0, nil, err
		}
		result = messageBody
	}
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(result)))
	base64.RawStdEncoding.Encode(encoded, result)
	return messageType, encoded, nil
}

// Decrypt decrypts a base64 encoded message using the Session.
func (os *OlmSession) Decrypt(crypttext []byte, msgType id.OlmMsgType) ([]byte, error) {
	if len(crypttext) == 0 {
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrEmptyInput)
	}
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(crypttext)))
	writtenBytes, err := base64.RawStdEncoding.Decode(decoded, crypttext)
	if err != nil {
		return nil, err
	}
	decodedCrypttext := decoded[:writtenBytes]
	msgBody := decodedCrypttext
	if msgType != id.OlmMsgTypeMsg {
		//Pre-Key Message
		msg := message.PreKeyMessage{}
		err := msg.Decode(decodedCrypttext)
		if err != nil {
			return nil, err
		}
		msgBody = msg.Message
	}
	plaintext, err := os.Ratchet.Decrypt(msgBody)
	if err != nil {
		return nil, err
	}
	os.ReceivedMessage = true
	return plaintext, nil
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (os *OlmSession) Unpickle(pickled, key []byte) error {
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = os.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Session accordingly. It returns the number of bytes read.
func (os *OlmSession) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	includesChainIndex := true
	switch pickledVersion {
	case olmSessionPickleVersionLibOlm:
		includesChainIndex = false
	case uint32(0x80000001):
		includesChainIndex = true
	default:
		return 0, fmt.Errorf("unpickle olmSession: %w", goolm.ErrBadVersion)
	}
	var readBytes int
	os.ReceivedMessage, readBytes, err = libolmpickle.UnpickleBool(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = os.AliceIdentityKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = os.AliceBaseKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = os.BobOneTimeKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = os.Ratchet.UnpickleLibOlm(value[curPos:], includesChainIndex)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled olmSession using PickleLibOlm().
func (os *OlmSession) Pickle(key []byte) ([]byte, error) {
	pickeledBytes := make([]byte, os.PickleLen())
	written, err := os.PickleLibOlm(pickeledBytes)
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
func (os *OlmSession) PickleLibOlm(target []byte) (int, error) {
	if len(target) < os.PickleLen() {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(olmSessionPickleVersionLibOlm, target)
	written += libolmpickle.PickleBool(os.ReceivedMessage, target[written:])
	writtenRatchet, err := os.AliceIdentityKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenRatchet, err = os.AliceBaseKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenRatchet, err = os.BobOneTimeKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenRatchet, err = os.Ratchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	return written, nil
}

// PickleLen returns the actual number of bytes the pickled session will have.
func (os *OlmSession) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(olmSessionPickleVersionLibOlm)
	length += libolmpickle.PickleBoolLen(os.ReceivedMessage)
	length += os.AliceIdentityKey.PickleLen()
	length += os.AliceBaseKey.PickleLen()
	length += os.BobOneTimeKey.PickleLen()
	length += os.Ratchet.PickleLen()
	return length
}

// PickleLenMin returns the minimum number of bytes the pickled session must have.
func (os *OlmSession) PickleLenMin() int {
	length := libolmpickle.PickleUInt32Len(olmSessionPickleVersionLibOlm)
	length += libolmpickle.PickleBoolLen(os.ReceivedMessage)
	length += os.AliceIdentityKey.PickleLen()
	length += os.AliceBaseKey.PickleLen()
	length += os.BobOneTimeKey.PickleLen()
	length += os.Ratchet.PickleLenMin()
	return length
}

// Describe returns a string describing the current state of the session for debugging.
func (os *OlmSession) Describe() string {
	var res string
	if os.Ratchet.SenderChains.IsSet {
		res += fmt.Sprintf("sender chain index: %d ", os.Ratchet.SenderChains.CKey.Index)
	} else {
		res += "sender chain index: "
	}
	res += "receiver chain indicies:"
	for _, curChain := range os.Ratchet.ReceiverChains {
		res += fmt.Sprintf(" %d", curChain.CKey.Index)
	}
	res += " skipped message keys:"
	for _, curSkip := range os.Ratchet.SkippedMessageKeys {
		res += fmt.Sprintf(" %d", curSkip.MKey.Index)
	}
	return res
}
