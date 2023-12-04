package tapprotocol

import (
	"github.com/skythen/apdu"
)

func (tapProtocol *TapProtocol) InitRequest() ([]byte, error) {

	// This ISO Applet is like doing a status
	tapProtocol.Stack.Push("status")

	data := []byte{0xf0, 'C', 'o', 'i', 'n', 'k', 'i', 't', 'e', 'C', 'A', 'R', 'D', 'v', '1'}

	capdu := apdu.Capdu{Cla: 0x00, Ins: 0xa4, P1: 0x04, Data: data}

	bytes, err := capdu.Bytes()

	if err != nil {
		return nil, err
	}
	return bytes, nil

}
