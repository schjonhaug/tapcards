package tapprotocol

func (tapProtocol *TapProtocol) New(cvc string) (int, error) {

	//tapProtocol.transport.Connect()
	//TODO	defer tapProtocol.transport.Disconnect()

	return tapProtocol.new(cvc)

}

func (tapProtocol *TapProtocol) new(cvc string) (int, error) {

	return 0, nil
	/*
		 TODO
			if tapProtocol.currentCardNonce == [16]byte{} {
				// TODO tapProtocol.status()
			}

			// Check if we can open the next slot
			if tapProtocol.Satscard.ActiveSlot+1 >= tapProtocol.NumberOfSlots {

				return 0, errors.New("no more slots available")

			}

			fmt.Println("------------")
			fmt.Println("New")
			fmt.Println("------------")

			command := Command{Cmd: "new"}

			auth, err := tapProtocol.authenticate(cvc, command)

			if err != nil {
				fmt.Println(err)
				return 0, err
			}

			newCommand := newCommand{
				Command: command,
				Slot:    tapProtocol.Satscard.ActiveSlot,
				auth:    *auth,
			}

			data, err := tapProtocol.sendReceive(newCommand)

			if err != nil {
				return 0, err
			}
			newData, ok := data.(newData)

			if !ok {
				return 0, errors.New("incorrect data type")
			}
			fmt.Println("#######")
			fmt.Println("# NEW #")
			fmt.Println("#######")

			fmt.Println("Slot:             ", newData.Slot)

			tapProtocol.currentCardNonce = newData.CardNonce
			tapProtocol.Satscard.ActiveSlot = newData.Slot

			return newData.Slot, nil
	*/
}
