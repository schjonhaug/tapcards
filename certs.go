package tapcards

import (
	"log/slog"
)

func (satscard *Satscard) CertsRequest() ([]byte, error) {

	// Log the request for debugging purposes
	slog.Debug("Request certs")

	// If the current card nonce is zero, enqueue a status command
	if satscard.currentCardNonce == [16]byte{} {
		satscard.queue.enqueue("status")
	}

	// Enqueue the commands
	satscard.queue.enqueue("certs")
	satscard.queue.enqueue("read")
	satscard.queue.enqueue("check")

	// Return the next command to be sent to the card
	return satscard.nextCommand()
}

// certsRequest is a method of the Satscard struct. It creates a certs command and wraps it into an APDU command.
// It then returns the byte representation of the APDU command.
func (satscard *Satscard) certsRequest() ([]byte, error) {

	// Create a certs command
	certsCommand := certsCommand{
		command{Cmd: "certs"},
	}

	// Wrap the command into an APDU command and return it
	return apduWrap(certsCommand)
}

// parseCertsData is a method of the Satscard struct. It takes a certsData struct as a parameter and parses it.
// It then assigns the CertificateChain field of the certsData to the certificateChain field of the Satscard.
// It returns an error if something goes wrong.
func (satscard *Satscard) parseCertsData(certsData certsData) error {

	// Log the parsing for debugging purposes
	slog.Debug("Parse certs")

	// Assign the CertificateChain field of the certsData to the certificateChain field of the Satscard
	satscard.certificateChain = certsData.CertificateChain

	// Return nil as there is no error
	return nil
}
