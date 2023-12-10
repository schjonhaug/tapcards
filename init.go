package tapprotocol

import (
	"github.com/skythen/apdu"
)

// ISO Applet Select
func (tapProtocol *TapProtocol) InitRequest() (cmd []byte, error error) {

	// This ISO Applet is equivalent to doing a "status" command
	tapProtocol.Queue.Enqueue("status")

	data := []byte{0xf0, 'C', 'o', 'i', 'n', 'k', 'i', 't', 'e', 'C', 'A', 'R', 'D', 'v', '1'}

	capdu := apdu.Capdu{Cla: 0x00, Ins: 0xa4, P1: 0x04, Data: data}

	return capdu.Bytes()

}
