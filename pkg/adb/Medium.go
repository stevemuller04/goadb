package adb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"time"
)

type Medium interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}

type NetMedium struct {
	conn *net.TCPConn
}

func NewNetMedium(conn *net.TCPConn) (NetMedium, error) {
	if conn == nil {
		return NetMedium{}, errors.New("TCP connection must not be nil")
	} else {
		return NetMedium{conn}, nil
	}
}

func (m NetMedium) Read(b []byte) (n int, err error) {
	return m.conn.Read(b)
}

func (m NetMedium) SetReadDeadline(t time.Time) error {
	return m.conn.SetReadDeadline(t)
}

func (m NetMedium) Write(b []byte) (n int, err error) {
	return m.conn.Write(b)
}

func (m NetMedium) SetWriteDeadline(t time.Time) error {
	return m.conn.SetWriteDeadline(t)
}

func (m NetMedium) Close() error {
	return m.conn.Close()
}

func WriteMessage(medium Medium, msg Message) error {
	var header [24]byte

	binary.LittleEndian.PutUint32(header[0:], msg.Command)
	binary.LittleEndian.PutUint32(header[4:], msg.Arg1)
	binary.LittleEndian.PutUint32(header[8:], msg.Arg2)
	binary.LittleEndian.PutUint32(header[12:], uint32(len(msg.Data)))
	binary.LittleEndian.PutUint32(header[16:], crc32.ChecksumIEEE(msg.Data))
	binary.LittleEndian.PutUint32(header[20:], msg.Command ^ 0xFFFFFFFF)

	if _, err := medium.Write(header[:]); err != nil {
		return fmt.Errorf("Unable to write message header (%d bytes): %w", len(header), err)
	} else if _, err := medium.Write(msg.Data); err != nil {
		return fmt.Errorf("Unable to write message body (%d bytes): %w", len(msg.Data), err)
	} else {
		return nil
	}
}

func ReadMessage(medium Medium) (Message, error) {
	var msg Message
	var header [24]byte

	if _, err := io.ReadAtLeast(medium, header[:], 24); err != nil {
		return msg, fmt.Errorf("Unable to read message header (%d bytes): %w", len(header), err)
	}

	msg.Command = binary.LittleEndian.Uint32(header[0:])
	msg.Arg1 = binary.LittleEndian.Uint32(header[4:])
	msg.Arg2 = binary.LittleEndian.Uint32(header[8:])
	length := int(binary.LittleEndian.Uint32(header[12:]))

	// Read body
	msg.Data = make([]byte, length)
	if _, err := io.ReadAtLeast(medium, msg.Data, length); err != nil {
		return msg, fmt.Errorf("Unable to read message body (%d bytes): %w", length, err)
	}

	return msg, nil
}

func WriteMessageWithTimeout(medium Medium, msg Message, timeout time.Duration) error {
	if timeout > 0 {
		if err := medium.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("Unable to set sending deadline: %w", err)
		}
	}
	return WriteMessage(medium, msg)
}

func ReadMessageWithTimeout(medium Medium, timeout time.Duration) (Message, error) {
	if timeout > 0 {
		if err := medium.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return Message{}, fmt.Errorf("Unable to set receival deadline: %w", err)
		}
	}
	return ReadMessage(medium)
}
