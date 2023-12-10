# Coinkite Tap Protocol Go

![Gopher](Gopher.png)

This is a implementation of the [Tap Cards protocol](https://dev.coinkite.cards/docs/protocol.html) written in [Go](https://go.dev). The current version focuses solely on the [Satscard](https://satscard.com), and not [Tapsigner](https://tapsigner.com) nor [Satschip](https://satschip.com).

## Satscard commands

The following Satscard commands are implemented

* [status](https://dev.coinkite.cards/docs/protocol.html#status)
* [read](https://dev.coinkite.cards/docs/protocol.html#read)
* [certs](https://dev.coinkite.cards/docs/protocol.html#certs)
* [new](https://dev.coinkite.cards/docs/protocol.html#new)
* [unseal](https://dev.coinkite.cards/docs/protocol.html#unseal)
* [wait](https://dev.coinkite.cards/docs/protocol.html#wait)

## Compile for mobile

```shell
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/bind
gomobile init
gomobile bind
```
