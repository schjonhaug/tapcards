package tapprotocol

import (
	"errors"
	"fmt"
)

func (tapProtocol *TapProtocol) Wait() (int, error) {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	waitData, err := tapProtocol.wait()

	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	return waitData.AuthDelay, nil

}
func (tapProtocol *TapProtocol) wait() (*waitData, error) {

	fmt.Println("----------------------------")
	fmt.Println("Wait")
	fmt.Println("----------------------------")

	statusCommand := statusCommand{command{Cmd: "wait"}}

	data, err := tapProtocol.sendReceive(statusCommand)

	fmt.Println("########")
	fmt.Println("# WAIT #")
	fmt.Println("########")

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	waitData, ok := data.(waitData)

	if !ok {
		return nil, errors.New("incorrect data type")
	}

	return &waitData, nil

}
