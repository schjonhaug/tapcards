# Coinkite Tap Protocol Go

![Gopher](gopher.png)

This is a implementation of the [Tap Cards protocol](https://dev.coinkite.cards/docs/protocol.html) written in [Go](https://go.dev). The current version focuses solely on the [Satscard](https://satscard.com), and not [Tapsigner](https://tapsigner.com) nor [Satschip](https://satschip.com).

## Satscard commands

The following Satscard commands are implemented

* [status](https://dev.coinkite.cards/docs/protocol.html#status)
* [read](https://dev.coinkite.cards/docs/protocol.html#read)
* [certs](https://dev.coinkite.cards/docs/protocol.html#certs)
* [new](https://dev.coinkite.cards/docs/protocol.html#new)
* [unseal](https://dev.coinkite.cards/docs/protocol.html#unseal)
* [wait](https://dev.coinkite.cards/docs/protocol.html#wait)

## How to use

### First step

Before any other commands are sent to a card, you must first do an “ISO Applet Select”. As long as the card remains powered-up (in the RF field) you do not need to repeat this command.

Then, you can run any of the command followed by `Request` to get a byte array which should be sent to the card. The library handles the details of APDU, so you can just send the raw bytes directly. The response from the card is a byte array which in turns need to be sent to `ParseResponse`. Some of the commands require multiple back-and-forth passes, so if you get a byte array from `ParseResponse`, it should be sent back to the cards, etc.

Finally, when there are no more data in return from `ParseResponse`, you can call on `Satscard` to get info about the card, private keys, etc.

## Building mobile libraries

The Go library can be compiled to Objective-C on iOS and Java on Android, making it work in mobile applications.

### Prerequisites

#### iOS

To build for iOS, you need to run macOS with either
[Command Line Tools](https://developer.apple.com/download/all/?q=command%20line%20tools)
or [Xcode](https://apps.apple.com/app/xcode/id497799835) installed.

#### Android

To build for Android, you need either
[Android Studio](https://developer.android.com/studio) or
[Command Line Tools](https://developer.android.com/studio#downloads) installed, which in turn must be used to install [Android NDK](https://developer.android.com/ndk/).

### Compile for mobile

```shell
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/bind
gomobile init
gomobile bind -target=ios
gomobile bind -target=android
```
