package message

import (
	"bytes"

	"maunium.net/go/mautrix/crypto/goolm/cipher"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
)

const (
	ratchetKeyTag        = 0x0A
	counterTag           = 0x10
	cipherTextKeyTag     = 0x22
	countMACBytesMessage = 8
)

// GroupMessage represents a message in the message format.
type Message struct {
	Version    byte                       `json:"version"`
	HasCounter bool                       `json:"has_counter"`
	Counter    uint32                     `json:"counter"`
	RatchetKey crypto.Curve25519PublicKey `json:"ratchet_key"`
	Ciphertext []byte                     `json:"ciphertext"`
}

// Decodes decodes the input and populates the corresponding fileds. MAC is ignored but has to be present.
func (m *Message) Decode(input []byte) error {
	m.Version = 0
	m.HasCounter = false
	m.Counter = 0
	m.RatchetKey = nil
	m.Ciphertext = nil
	if len(input) == 0 {
		return nil
	}
	//first Byte is always version
	m.Version = input[0]
	curPos := 1
	for curPos < len(input)-countMACBytesMessage {
		//Read Key
		curKey, readBytes := decodeVarInt(input[curPos:])
		if err := checkDecodeErr(readBytes); err != nil {
			return err
		}
		curPos += readBytes
		if (curKey & 0b111) == 0 {
			//The value is of type varint
			value, readBytes := decodeVarInt(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
			switch curKey {
			case counterTag:
				m.HasCounter = true
				m.Counter = value
			}
		} else if (curKey & 0b111) == 2 {
			//The value is of type string
			value, readBytes := decodeVarString(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
			switch curKey {
			case ratchetKeyTag:
				m.RatchetKey = value
			case cipherTextKeyTag:
				m.Ciphertext = value
			}
		}
	}

	return nil
}

// EncodeAndMAC encodes the message and creates the MAC with the key and the cipher.
// If key or cipher is nil, no MAC is appended.
func (m *Message) EncodeAndMAC(key []byte, cipher cipher.Cipher) ([]byte, error) {
	var lengthOfMessage int
	lengthOfMessage += 1 //Version
	lengthOfMessage += encodeVarIntByteLength(ratchetKeyTag) + encodeVarStringByteLength(m.RatchetKey)
	lengthOfMessage += encodeVarIntByteLength(counterTag) + encodeVarIntByteLength(m.Counter)
	lengthOfMessage += encodeVarIntByteLength(cipherTextKeyTag) + encodeVarStringByteLength(m.Ciphertext)
	out := make([]byte, lengthOfMessage)
	out[0] = m.Version
	curPos := 1
	encodedTag := encodeVarInt(ratchetKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue := encodeVarString(m.RatchetKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(counterTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarInt(m.Counter)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(cipherTextKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(m.Ciphertext)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	if len(key) != 0 && cipher != nil {
		mac, err := cipher.MAC(key, out)
		if err != nil {
			return nil, err
		}
		out = append(out, mac[:countMACBytesMessage]...)
	}
	return out, nil
}

// VerifyMAC verifies the givenMAC to the calculated MAC of the message.
func (m *Message) VerifyMAC(key []byte, cipher cipher.Cipher, message, givenMAC []byte) (bool, error) {
	checkMAC, err := cipher.MAC(key, message)
	if err != nil {
		return false, err
	}
	return bytes.Equal(checkMAC[:countMACBytesMessage], givenMAC), nil
}

// VerifyMACInline verifies the MAC taken from the message to the calculated MAC of the message.
func (m *Message) VerifyMACInline(key []byte, cipher cipher.Cipher, message []byte) (bool, error) {
	givenMAC := message[len(message)-countMACBytesMessage:]
	return m.VerifyMAC(key, cipher, message[:len(message)-countMACBytesMessage], givenMAC)
}
