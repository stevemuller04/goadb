package adb

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
)

type Client struct {
	medium Medium
	privateKey *rsa.PrivateKey
}

func NewClient(privateKey *rsa.PrivateKey) (Client, error) {
	if privateKey == nil {
		return Client{}, errors.New("Private key must not be null")
	} else {
		return Client{nil, privateKey}, nil
	}
}

func (c *Client) ConnectWith(conn *net.TCPConn) error {
	if medium, err := NewNetMedium(conn); err != nil {
		return fmt.Errorf("Cannot instantiate medium: %w", err)
	} else {
		c.medium = medium
		return nil
	}
}

func (c *Client) ConnectTo(deviceAddr string) error {
	if tcpAddr, err := net.ResolveTCPAddr("tcp", deviceAddr); err != nil {
		return fmt.Errorf("Unable to resolve %v: %w", deviceAddr, err)
	} else if tcpConn, err := net.DialTCP("tcp", nil, tcpAddr); err != nil {
		return fmt.Errorf("Unable to connect to %v: %w", tcpAddr, err)
	} else {
		return c.ConnectWith(tcpConn)
	}
}

func (c *Client) Close() error {
	if c.medium != nil {
		if err := c.medium.Close(); err != nil {
			return fmt.Errorf("Unable to close medium: %w", err)
		}
	}
	return nil
}

func (c *Client) Handshake(systemIdentityString string) ([]byte, error) {
	if c.medium == nil {
		return nil, errors.New("Medium is not initialized")
	} else if err := WriteMessage(c.medium, NewMessage_Connect(systemIdentityString)); err != nil {
		return nil, fmt.Errorf("Unable to send CONNECT message: %w", err)
	} else if msg1, err := ReadMessage(c.medium); err != nil {
		return nil, fmt.Errorf("Error while receiving response to CONNECT: %w", err)
	} else if msg1.Command != MessageCommand_Auth {
		return nil, errors.New("Expected AUTH response to CONNECT request")
	} else if signature, err := sign(msg1.Data, c.privateKey); err != nil {
		return nil, fmt.Errorf("Unable to sign challenge with own private key: %w", err)
	} else if err := WriteMessage(c.medium, NewMessage_Auth_Signature(signature)); err != nil {
		return nil, fmt.Errorf("Unable to send AUTH+signature request: %w")
	} else if msg2, err := ReadMessage(c.medium); err != nil {
		return nil, fmt.Errorf("Error while receiving response to AUTH+signature request: %w", err)
	} else if msg2.Command == MessageCommand_Connect {
		// Success; device accepted our signature
		return msg2.Data, nil
	} else if msg2.Command != MessageCommand_Auth {
		return nil, fmt.Errorf("Expected CONNECT or AUTH response to AUTH+signature request: %w", err)
	} else if err := WriteMessage(c.medium, NewMessage_Auth_PublicKey(encodePublicKey(&c.privateKey.PublicKey))); err != nil {
		return nil, fmt.Errorf("Unable to send AUTH+publickey request: %w", err)
	} else if msg3, err := ReadMessage(c.medium); err != nil {
		return nil, fmt.Errorf("Error while receiving response to AUTH+publickey request: %w", err)
	} else if msg3.Command == MessageCommand_Connect {
		// Success; device accepted our public key
		return msg3.Data, nil
	} else {
		return nil, errors.New("Device did not accept our key")
	}
}

func sign(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	if len(data) != 20 {
		return nil, errors.New(fmt.Sprintf("Authentication challenge must be 20 bytes long, got %d bytes", len(data)))
	} else if signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, data); err != nil {
		return nil, fmt.Errorf("Signing authentication challenge failed: %w", err)
	} else {
		return signature, nil
	}
}

func encodePublicKey(publicKey *rsa.PublicKey) []byte {
	// from https://cs.android.com/android/platform/superproject/+/master:system/core/libcrypto_utils/android_pubkey.cpp

	const ANDROID_PUBKEY_MODULUS_SIZE = 0x100
	var encoded [4 + 4 + ANDROID_PUBKEY_MODULUS_SIZE + ANDROID_PUBKEY_MODULUS_SIZE + 4]byte
	encodedPtr := encoded[:]

	// Modulus length, in words (uint32)
	binary.LittleEndian.PutUint32(encodedPtr[:4], ANDROID_PUBKEY_MODULUS_SIZE / 4)
	encodedPtr = encodedPtr[4:]

	// Precomputed montgomery parameter: -1 / n[0] mod 2^32
	r32 := big.NewInt(0x100000000) // 2^32
	n0inv := big.NewInt(0)
	n0inv.Mod(publicKey.N, r32)
	n0inv.ModInverse(n0inv, r32)
	n0inv.Sub(r32, n0inv)
	n0inv.FillBytes(encodedPtr[:4])
	bigToLittleEndian(encodedPtr[:4])
	encodedPtr = encodedPtr[4:]

	// RSA modulus as a little-endian array.
	publicKey.N.FillBytes(encodedPtr[:ANDROID_PUBKEY_MODULUS_SIZE])
	bigToLittleEndian(encodedPtr[:ANDROID_PUBKEY_MODULUS_SIZE])
	encodedPtr = encodedPtr[ANDROID_PUBKEY_MODULUS_SIZE:]

	// Montgomery parameter R^2 as a little-endian array.
	// rr = (2^(rsa_size)) ^ 2 mod N
	rr := big.NewInt(0)
	rr.SetBit(rr, ANDROID_PUBKEY_MODULUS_SIZE * 8, 1)
	rr.Mul(rr, rr)
	rr.Mod(rr, publicKey.N)
	rr.FillBytes(encodedPtr[:ANDROID_PUBKEY_MODULUS_SIZE])
	bigToLittleEndian(encodedPtr[:ANDROID_PUBKEY_MODULUS_SIZE])
	encodedPtr = encodedPtr[ANDROID_PUBKEY_MODULUS_SIZE:]

	// RSA exponent: 3 or 65537
	binary.LittleEndian.PutUint32(encodedPtr[:4], uint32(publicKey.E))

	return []byte(base64.StdEncoding.EncodeToString(encoded[:]) + "\x00")
}

func bigToLittleEndian(s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
