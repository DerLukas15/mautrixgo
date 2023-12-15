package olm

import (
	"fmt"

	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
)

// skippedMessageKey stores a skipped message key
type skippedMessageKey struct {
	RKey crypto.Curve25519PublicKey `json:"ratchet_key"`
	MKey messageKey                 `json:"message_key"`
}

// UnpickleLibOlm decodes the unencryted value and populates the chain accordingly. It returns the number of bytes read.
func (smk *skippedMessageKey) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := smk.RKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = smk.MKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm encodes the chain into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (smk *skippedMessageKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < smk.PickleLen() {
		return 0, fmt.Errorf("pickle sender chain: %w", goolm.ErrValueTooShort)
	}
	written, err := smk.RKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	writtenChain, err := smk.MKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	written += writtenChain
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain will have.
func (smk *skippedMessageKey) PickleLen() int {
	length := smk.RKey.PickleLen()
	length += smk.MKey.PickleLen()
	return length
}
