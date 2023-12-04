package tapprotocol

func (tapProtocol *TapProtocol) Wait() (int, error) {

	return 0, nil
	/* TODO
	   	tapProtocol.transport.Connect()
	   	defer tapProtocol.transport.Disconnect()

	   	waitData, err := tapProtocol.wait()

	   	if err != nil {

	   		return 0, err
	   	}

	   	return waitData.AuthDelay, nil

	   }
	   func (tapProtocol *TapProtocol) wait() (*waitData, error) {

	   	fmt.Println("----------------------------")
	   	fmt.Println("Wait")
	   	fmt.Println("----------------------------")

	   	waitCommand := waitCommand{Command{Cmd: "wait"}}

	   	data, err := tapProtocol.sendReceive(waitCommand)

	   	fmt.Println("########")
	   	fmt.Println("# WAIT #")
	   	fmt.Println("########")

	   	if err != nil {

	   		return nil, err
	   	}

	   	waitData, ok := data.(waitData)

	   	if !ok {
	   		return nil, errors.New("incorrect data type")
	   	}

	   	return &waitData, nil

	*/

}
