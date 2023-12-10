# Coinkite Tap Protocol Go

## Satscard commands

The following Satscard commands are implemented

* status
* read
* certs
* new
* unseal

## Compile for mobile

```shell
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/bind
gomobile init
gomobile bind -target=ios
```
