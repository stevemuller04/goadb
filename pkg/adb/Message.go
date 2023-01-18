package adb

import (
	"encoding/binary"
	"fmt"
)

const (
	MessageCommand_Auth = 0x48545541
	MessageCommand_Close = 0x45534C43
	MessageCommand_Connect = 0x4E584E43
	MessageCommand_Okay = 0x59414B4F
	MessageCommand_Open = 0x4E45504F
	MessageCommand_StartTLS = 0x534C5453
	MessageCommand_Sync = 0x434E5953
	MessageCommand_Write = 0x45545257
)

type Message struct {
	Command uint32
	Arg1 uint32
	Arg2 uint32
	Data []byte
}

func NewMessage_Connect(systemIdentityString string) Message {
	return Message { MessageCommand_Connect, /*version:*/ 0x01000000, /*maxdata:*/ 0x1000, []byte(systemIdentityString) }
}

func NewMessage_Auth_Signature(signature []byte) Message {
	return Message { MessageCommand_Auth, 2, 0, signature }
}

func NewMessage_Auth_PublicKey(publicKey []byte) Message {
	return Message { MessageCommand_Auth, 3, 0, publicKey }
}

func (m Message) String() string {
	var cmd [4]byte
	binary.LittleEndian.PutUint32(cmd[:], m.Command)
	return fmt.Sprintf("Message(%s,%d,%d){%X}", cmd, m.Arg1, m.Arg2, m.Data)
}
