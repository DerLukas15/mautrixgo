package olm

import (
	"fmt"

	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
)

const (
	chainKeySeed     = 0x02
	messageKeyLength = 32
)

// chainKey wraps the index and the public key
type chainKey struct {
	Index uint32                     `json:"index"`
	Key   crypto.Curve25519PublicKey `json:"key"`
}

// advance advances the chain
func (ck *chainKey) advance() {
	ck.Key = crypto.HMACSHA256(ck.Key, []byte{chainKeySeed})
	ck.Index++
}

// UnpickleLibOlm decodes the unencryted value and populates the chain key accordingly. It returns the number of bytes read.
func (ck *chainKey) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := ck.Key.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	ck.Index, readBytes, err = libolmpickle.UnpickleUInt32(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm encodes the chain key into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (ck *chainKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < ck.PickleLen() {
		return 0, fmt.Errorf("pickle chain key: %w", goolm.ErrValueTooShort)
	}
	written, err := ck.Key.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle chain key: %w", err)
	}
	written += libolmpickle.PickleUInt32(ck.Index, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain key will have.
func (ck *chainKey) PickleLen() int {
	length := ck.Key.PickleLen()
	length += libolmpickle.PickleUInt32Len(ck.Index)
	return length
}

// senderChain is a chain for sending messages
type senderChain struct {
	RKey  crypto.Curve25519KeyPair `json:"ratchet_key"`
	CKey  chainKey                 `json:"chain_key"`
	IsSet bool                     `json:"set"`
}

// newSenderChain returns a sender chain initialized with chainKey and ratchet key pair.
func newSenderChain(key crypto.Curve25519PublicKey, ratchet crypto.Curve25519KeyPair) *senderChain {
	return &senderChain{
		RKey: ratchet,
		CKey: chainKey{
			Index: 0,
			Key:   key,
		},
		IsSet: true,
	}
}

// advance advances the chain
func (sc *senderChain) advance() {
	sc.CKey.advance()
}

// ratchetKey returns the ratchet key pair.
func (sc *senderChain) ratchetKey() crypto.Curve25519KeyPair {
	return sc.RKey
}

// chainKey returns the current chainKey.
func (sc *senderChain) chainKey() chainKey {
	return sc.CKey
}

// UnpickleLibOlm decodes the unencryted value and populates the chain accordingly. It returns the number of bytes read.
func (sc *senderChain) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := sc.RKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = sc.CKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm encodes the chain into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (sc *senderChain) PickleLibOlm(target []byte) (int, error) {
	if len(target) < sc.PickleLen() {
		return 0, fmt.Errorf("pickle sender chain: %w", goolm.ErrValueTooShort)
	}
	written, err := sc.RKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	writtenChain, err := sc.CKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	written += writtenChain
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain will have.
func (sc *senderChain) PickleLen() int {
	length := sc.RKey.PickleLen()
	length += sc.CKey.PickleLen()
	return length
}

// senderChain is a chain for receiving messages
type receiverChain struct {
	RKey crypto.Curve25519PublicKey `json:"ratchet_key"`
	CKey chainKey                   `json:"chain_key"`
}

// newReceiverChain returns a receiver chain initialized with chainKey and ratchet public key.
func newReceiverChain(chain crypto.Curve25519PublicKey, ratchet crypto.Curve25519PublicKey) *receiverChain {
	return &receiverChain{
		RKey: ratchet,
		CKey: chainKey{
			Index: 0,
			Key:   chain,
		},
	}
}

// advance advances the chain
func (rc *receiverChain) advance() {
	rc.CKey.advance()
}

// ratchetKey returns the ratchet public key.
func (rc *receiverChain) ratchetKey() crypto.Curve25519PublicKey {
	return rc.RKey
}

// chainKey returns the current chainKey.
func (rc *receiverChain) chainKey() chainKey {
	return rc.CKey
}

// UnpickleLibOlm decodes the unencryted value and populates the chain accordingly. It returns the number of bytes read.
func (rc *receiverChain) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := rc.RKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = rc.CKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm encodes the chain into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (rc *receiverChain) PickleLibOlm(target []byte) (int, error) {
	if len(target) < rc.PickleLen() {
		return 0, fmt.Errorf("pickle sender chain: %w", goolm.ErrValueTooShort)
	}
	written, err := rc.RKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	writtenChain, err := rc.CKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	written += writtenChain
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain will have.
func (rc *receiverChain) PickleLen() int {
	length := rc.RKey.PickleLen()
	length += rc.CKey.PickleLen()
	return length
}

// messageKey wraps the index and the key of a message
type messageKey struct {
	Index uint32 `json:"index"`
	Key   []byte `json:"key"`
}

// UnpickleLibOlm decodes the unencryted value and populates the message key accordingly. It returns the number of bytes read.
func (mk *messageKey) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	ratchetKey, readBytes, err := libolmpickle.UnpickleBytes(value, messageKeyLength)
	if err != nil {
		return 0, err
	}
	mk.Key = ratchetKey
	curPos += readBytes
	keyID, readBytes, err := libolmpickle.UnpickleUInt32(value[:curPos])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	mk.Index = keyID
	return curPos, nil
}

// PickleLibOlm encodes the message key into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (mk *messageKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < mk.PickleLen() {
		return 0, fmt.Errorf("pickle message key: %w", goolm.ErrValueTooShort)
	}
	written := 0
	if len(mk.Key) != messageKeyLength {
		written += libolmpickle.PickleBytes(make([]byte, messageKeyLength), target)
	} else {
		written += libolmpickle.PickleBytes(mk.Key, target)
	}
	written += libolmpickle.PickleUInt32(mk.Index, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled message key will have.
func (mk *messageKey) PickleLen() int {
	length := libolmpickle.PickleBytesLen(make([]byte, messageKeyLength))
	length += libolmpickle.PickleUInt32Len(mk.Index)
	return length
}
