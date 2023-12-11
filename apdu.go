package tapcards

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/skythen/apdu"
)

// apduWrap takes any value, serializes it using CBOR, and wraps it into an APDU command.
// It returns the byte representation of the APDU command or an error if something goes wrong.
func apduWrap(value interface{}) ([]byte, error) {

	cborSerialized, err := cbor.Marshal(value)
	if err != nil {
		return nil, err
	}

	capdu := apdu.Capdu{Cla: 0x00, Ins: 0xCB, Data: cborSerialized}

	return capdu.Bytes()

}

// apduUnwrap takes a byte slice, tries to parse it as an APDU response, and returns the data field of the response.
// It returns an error if the byte slice cannot be parsed as an APDU response.
func apduUnwrap(value []byte) ([]byte, error) {

	rapdu, err := apdu.ParseRapdu(value)

	if err != nil {
		return nil, err

	}

	if rapdu.SW1 != 0x90 {
		return nil, fmt.Errorf("incorrect status word 1: %x", rapdu.SW1)
	}

	return rapdu.Data, nil

}
