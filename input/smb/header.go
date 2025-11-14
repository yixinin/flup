package smb

import (
	"bytes"
	"encoding/binary"
)

// SMB命令码
const (
	SMB_COM_NEGOTIATE       = 0x72 // 114
	SMB_COM_SESSION_SETUP   = 0x73 // 115
	SMB_COM_TREE_CONNECT    = 0x75 // 117
	SMB_COM_NT_CREATE_ANDX  = 0xA2 // 162
	SMB_COM_WRITE_ANDX      = 0x2F // 47
	SMB_COM_READ_ANDX       = 0x2E // 46
	SMB_COM_CLOSE           = 0x04 // 4
	SMB_COM_TREE_DISCONNECT = 0x71 // 113
	SMB_COM_LOGOFF          = 0x74 // 116
)

// SMB标志和功能
const (
	SMB_FLAGS_CANONICALIZED_PATHS = 0x10   // 16
	SMB_FLAGS_CASE_INSENSITIVE    = 0x08   // 8
	SMB_FLAGS2_UNICODE            = 0x8000 // 32768
	SMB_FLAGS2_EXTENDED_SECURITY  = 0x0800 // 2048

	// 文件创建选项
	FILE_CREATE  = 0x10 // 16
	FILE_OPEN    = 0x01 // 1
	FILE_OPEN_IF = 0x03 // 3

	// 文件共享模式
	FILE_SHARE_READ   = 0x01 // 1
	FILE_SHARE_WRITE  = 0x02 // 2
	FILE_SHARE_DELETE = 0x04 // 4

	// 文件属性
	FILE_ATTRIBUTE_DIRECTORY = 0x10 // 16
	FILE_ATTRIBUTE_NORMAL    = 0x80 // 128
)

// SMB头结构
type SMBHeader struct {
	Protocol  [4]byte
	Command   uint8
	Status    uint32
	Flags     uint8
	Flags2    uint16
	PIDHigh   uint16
	Security  [8]byte
	Reserved  uint16
	TID       uint16
	PIDLow    uint16
	UID       uint16
	MID       uint16
	WordCount uint8
	ByteCount uint16
}

// Serialize writes the SMBHeader to a buffer in network byte order
func (h *SMBHeader) Serialize(buf *bytes.Buffer) error {
	// Write protocol identifier
	buf.Write(h.Protocol[:])
	// Write command
	buf.WriteByte(h.Command)
	// Write status (4 bytes, little-endian)
	statusBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(statusBytes, h.Status)
	buf.Write(statusBytes)
	// Write flags
	buf.WriteByte(h.Flags)
	// Write flags2 (2 bytes, little-endian)
	flags2Bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(flags2Bytes, h.Flags2)
	buf.Write(flags2Bytes)
	// Write PIDHigh (2 bytes, little-endian)
	pidHighBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(pidHighBytes, h.PIDHigh)
	buf.Write(pidHighBytes)
	// Write security blob
	buf.Write(h.Security[:])
	// Write reserved (2 bytes, little-endian)
	reservedBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(reservedBytes, h.Reserved)
	buf.Write(reservedBytes)
	// Write TID (2 bytes, little-endian)
	tidBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(tidBytes, h.TID)
	buf.Write(tidBytes)
	// Write PIDLow (2 bytes, little-endian)
	pidLowBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(pidLowBytes, h.PIDLow)
	buf.Write(pidLowBytes)
	// Write UID (2 bytes, little-endian)
	uidBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(uidBytes, h.UID)
	buf.Write(uidBytes)
	// Write MID (2 bytes, little-endian)
	midBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(midBytes, h.MID)
	buf.Write(midBytes)
	// Write WordCount
	buf.WriteByte(h.WordCount)
	// Write ByteCount (2 bytes, little-endian)
	byteCountBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(byteCountBytes, h.ByteCount)
	buf.Write(byteCountBytes)
	return nil
}

// 文件句柄管理
type FileHandle struct {
	FID      uint16
	Filename string
}
