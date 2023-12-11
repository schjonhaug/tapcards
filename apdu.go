package tapcards

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/skythen/apdu"
)

func apduWrap(value interface{}) ([]byte, error) {

	cborSerialized, err := cbor.Marshal(value)
	if err != nil {
		return nil, err
	}

	capdu := apdu.Capdu{Cla: 0x00, Ins: 0xCB, Data: cborSerialized}

	return capdu.Bytes()

}

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
