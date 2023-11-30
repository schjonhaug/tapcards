package tapprotocol

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Transport struct {
	EphemeralPubKey []byte
	XCVC            []byte
}

func (transport *Transport) reader(r io.Reader, command any, channel chan any) {
	buf := make([]byte, 1024)
	_, err := r.Read(buf[:])

	if err != nil {
		print(err)
		return
	}

	decMode, _ := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()

	fmt.Println("Switch on command", command)

	switch command.(type) {
	case statusCommand:

		var v statusData

		if err := decMode.Unmarshal(buf, &v); err != nil {
			panic(err)
		}

		channel <- v

	case unsealCommand:

		var v UnsealData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				panic(err)
			}

			channel <- e

		}

		channel <- v
	case newCommand:

		var v NewData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				panic(err)
			}

			channel <- e

		}

		channel <- v
	case certsCommand:

		var v certificatesData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				fmt.Println(err)

			}

			channel <- e

		}

		channel <- v
	case checkCommand:

		var v checkData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				fmt.Println(err)

			}

			channel <- e

		}

		channel <- v
	case readCommand:

		var v readData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				panic(err)
			}

			channel <- e

		}

		channel <- v

	default:

		var v ErrorData

		if err := decMode.Unmarshal(buf, &v); err != nil {
			panic(err)
		}

		channel <- v

		fmt.Println("Unknown command??")
	}

}

func (transport Transport) Send(command any, channel chan any) {

	cbor_serialized, err := cbor.Marshal(command)
	if err != nil {
		fmt.Println("error:", err)
	}

	connection, err := net.Dial("unix", "/tmp/ecard-pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()

	go transport.reader(connection, command, channel)
	_, err = connection.Write(cbor_serialized)

	if err != nil {
		log.Fatal("write error:", err)
	}

	time.Sleep(100 * time.Millisecond)

}
