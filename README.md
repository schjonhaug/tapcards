# Coinkite Tap Cards Protocol Implementation in Go

![Gopher Logo](gopher.png)

This project is a Go language implementation of the [Tap Cards protocol](https://dev.coinkite.cards/docs/protocol.html), specifically focusing on the [Satscard](https://satscard.com) functionality. It does not cover [Tapsigner](https://tapsigner.com) or [Satschip](https://satschip.com) functionalities at this time.

## Available Satscard Commands

Implemented commands for Satscard include:

* [status](https://dev.coinkite.cards/docs/protocol.html#status)
* [read](https://dev.coinkite.cards/docs/protocol.html#read)
* [certs](https://dev.coinkite.cards/docs/protocol.html#certs)
* [new](https://dev.coinkite.cards/docs/protocol.html#new)
* [unseal](https://dev.coinkite.cards/docs/protocol.html#unseal)
* [wait](https://dev.coinkite.cards/docs/protocol.html#wait)

## Usage Guide

### Initial Steps

The first action with a card is an `ISOAppletSelectRequest`. The library manages APDU complexities, allowing direct sending of raw bytes. The card’s response should be processed through `ParseResponse`. This step is not necessary to repeat as long as the card remains powered in the RF field.

Subsequently, run a `Request` command to generate a byte array for the card.  Multiple interactions may be necessary for some commands, with byte arrays from `ParseResponse` being resent to the card as needed. Once `ParseResponse` yields no further data, use `Satscard` to access card information, private keys, etc.

Always verify the factory certificate of the card before trusting any data from it. To do this, run `CertsRequest` which check the authenticity of the card. This command will also run the `read` command, which will expose the current receiving address.

## Building Mobile Libraries

The Go library can be compiled for mobile platforms, supporting Objective-C on iOS and Java on Android.

### Setup Requirements

#### For iOS

Requires macOS with [Command Line Tools](https://developer.apple.com/download/all/?q=command%20line%20tools) or [Xcode](https://apps.apple.com/app/xcode/id497799835).

#### For Android

Requires [Android Studio](https://developer.android.com/studio) or [Command Line Tools](https://developer.android.com/studio#downloads), and the installation of [Android NDK](https://developer.android.com/ndk/).

### Mobile Compilation Steps

```shell
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/bind
gomobile init
gomobile bind -target=ios
gomobile bind -target=android
```

## Examples

In the [examples folder](examples), there are two projects using this module. One using the emulator, and the other using physical Satscards.

## Development and debug

For the ongoing development and upkeep of this library, it is beneficial to utilise the [Python emulator](https://github.com/coinkite/coinkite-tap-proto/tree/master/emulator) provided by Coinkite. You can integrate the emulator with the library by executing `UseEmulator()`. Additionally, invoking `EnableDebugLogging()` will provide valuable information for debugging.
