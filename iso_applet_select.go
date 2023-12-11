package tapcards

import (
	"github.com/skythen/apdu"
)

// ISO Applet Select
func (tapProtocol *TapProtocol) ISOAppletSelectRequest() ([]byte, error) {

	// ISO Applet Select is equivalent to doing a "status" command
	tapProtocol.queue.enqueue("status")

	data := []byte{0xf0, 'C', 'o', 'i', 'n', 'k', 'i', 't', 'e', 'C', 'A', 'R', 'D', 'v', '1'}

	capdu := apdu.Capdu{Cla: 0x00, Ins: 0xa4, P1: 0x04, Data: data}

	return capdu.Bytes()

}
