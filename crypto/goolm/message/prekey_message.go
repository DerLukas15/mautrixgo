package message

import (
	"maunium.net/go/mautrix/crypto/goolm/crypto"
)

const (
	oneTimeKeyIdTag = 0x0A
	baseKeyTag      = 0x12
	identityKeyTag  = 0x1A
	messageTag      = 0x22
)

type PreKeyMessage struct {
	Version     byte                       `json:"version"`
	IdentityKey crypto.Curve25519PublicKey `json:"id_key"`
	BaseKey     crypto.Curve25519PublicKey `json:"base_key"`
	OneTimeKey  crypto.Curve25519PublicKey `json:"one_time_key"`
	Message     []byte                     `json:"message"`
}

// Decodes decodes the input and populates the corresponding fileds.
func (pkm *PreKeyMessage) Decode(input []byte) error {
	pkm.Version = 0
	pkm.IdentityKey = nil
	pkm.BaseKey = nil
	pkm.OneTimeKey = nil
	pkm.Message = nil
	if len(input) == 0 {
		return nil
	}
	//first Byte is always version
	pkm.Version = input[0]
	curPos := 1
	for curPos < len(input) {
		//Read Key
		curKey, readBytes := decodeVarInt(input[curPos:])
		if err := checkDecodeErr(readBytes); err != nil {
			return err
		}
		curPos += readBytes
		if (curKey & 0b111) == 0 {
			//The value is of type varint
			_, readBytes := decodeVarInt(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
		} else if (curKey & 0b111) == 2 {
			//The value is of type string
			value, readBytes := decodeVarString(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
			switch curKey {
			case oneTimeKeyIdTag:
				pkm.OneTimeKey = value
			case baseKeyTag:
				pkm.BaseKey = value
			case identityKeyTag:
				pkm.IdentityKey = value
			case messageTag:
				pkm.Message = value
			}
		}
	}

	return nil
}

// CheckField verifies the fields. If theirIdentityKey is nil, it is not compared to the key in the message.
func (pkm *PreKeyMessage) CheckFields(theirIdentityKey *crypto.Curve25519PublicKey) bool {
	ok := true
	ok = ok && (theirIdentityKey != nil || pkm.IdentityKey != nil)
	if pkm.IdentityKey != nil {
		ok = ok && (len(pkm.IdentityKey) == crypto.Curve25519KeyLength)
	}
	ok = ok && len(pkm.Message) != 0
	ok = ok && len(pkm.BaseKey) == crypto.Curve25519KeyLength
	ok = ok && len(pkm.OneTimeKey) == crypto.Curve25519KeyLength
	return ok
}

// Encode encodes the message.
func (pkm *PreKeyMessage) Encode() ([]byte, error) {
	var lengthOfMessage int
	lengthOfMessage += 1 //Version
	lengthOfMessage += encodeVarIntByteLength(oneTimeKeyIdTag) + encodeVarStringByteLength(pkm.OneTimeKey)
	lengthOfMessage += encodeVarIntByteLength(identityKeyTag) + encodeVarStringByteLength(pkm.IdentityKey)
	lengthOfMessage += encodeVarIntByteLength(baseKeyTag) + encodeVarStringByteLength(pkm.BaseKey)
	lengthOfMessage += encodeVarIntByteLength(messageTag) + encodeVarStringByteLength(pkm.Message)
	out := make([]byte, lengthOfMessage)
	out[0] = pkm.Version
	curPos := 1
	encodedTag := encodeVarInt(oneTimeKeyIdTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue := encodeVarString(pkm.OneTimeKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(identityKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(pkm.IdentityKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(baseKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(pkm.BaseKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(messageTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(pkm.Message)
	copy(out[curPos:], encodedValue)
	return out, nil
}
