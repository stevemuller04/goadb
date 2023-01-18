package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/stevemuller04/goadb/pkg/adb"
	"os"
)

var cli struct {
	PrivateKeyFile string `required:"" name:"privkey" short:"k" help:"Path to the PKCS#1 private key in PEM format"`
	DeviceAddr string `arg:"" help:"The hostname and port, separated by colon, of the Android device"`
}

func main() {
	kong.Parse(&cli)

	if key, err := loadPrivateKey(cli.PrivateKeyFile); err != nil {
		fmt.Printf("Cannot load private key: %s\n", err)
	} else if c, err := adb.NewClient(key); err != nil {
		fmt.Printf("Initialization error: %s\n", err)
	} else if err := c.ConnectTo(cli.DeviceAddr); err != nil {
		fmt.Printf("Connection error: %s\n", err)
	} else if deviceInfoData, err := c.Handshake("host::"); err != nil {
		fmt.Printf("Handshake error: %s\n", err)
	} else {
		fmt.Printf("Handshake OK\n")
		fmt.Printf("Device info: %s\n", deviceInfoData)
	}
}

func loadPrivateKey(filepath string) (*rsa.PrivateKey, error) {
	if bytes, err := os.ReadFile(filepath); err != nil {
		return nil, fmt.Errorf("Unable to read private key file at %s: %w", filepath, err)
	} else if data, _ := pem.Decode(bytes); data == nil {
		return nil, errors.New("Invalid PEM data")
	} else if privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes); err != nil {
		return nil, fmt.Errorf("Unable to parse PKCS#1 file at %s: %w", filepath, err)
	} else {
		return privateKey, nil
	}
}
