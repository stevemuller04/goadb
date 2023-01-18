# goadb

ADB client written in pure Go.

Currently only connections over TCP are supported, but the project is built in such a way that adding support for USB should be simple (see `Medium.go`).

## Build

Compile the binary using

```bash
go build -o build/ ./...
```

or just use `make` if you have `make` installed.

## Usage

Run the demo binary using

```bash
./build/goadb -k $PATH_TO_YOUR_PRIVATE_KEY_FILE $ANDROID_DEVICE_IP:$ANDROID_DEVICE_PORT
```

where:
* `$PATH_TO_YOUR_PRIVATE_KEY_FILE` is the path to an RSA 2048 private key in PEM format, which you can generate using `openssl genrsa`
* `$ANDROID_DEVICE_IP` is the IP address of your Android device, which you can see in your Android settings → System → Developer options → Wireless debugging
* `$ANDROID_DEVICE_PORT` is the port of the adb server on your Android device, which you can see in your Android settings → System → Developer options → Wireless debugging. If you have "Wireless ADB debugging" turned on in Developer options, you may also use port 5555.

Note that to use ADB, you need to enable Developer options on your phone, which you can do by tapping 7 times on Android settings → About phone → Build number.

# Acknowledgments

The library was built based on

* the offical documentation, which is very poor: https://android.googlesource.com/platform/packages/modules/adb/+/master/protocol.txt
* some more insight by C. Styan: https://github.com/cstyan/adbDocumentation
* reading the Android/adb source code

# Contribute

Currently the project can "only" do a handshake and send raw messages.
Implementing the remaining ADB messages on a higher level should not be too hard, so feel free to clone and contribute.
The library probably needs some adaptations when large files are transmitted, because currently the entire message is buffered in memory.
