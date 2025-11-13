package smb

import (
	"os"
)

// SMB命令码
const (
	SMB_COM_NEGOTIATE       = 0x72
	SMB_COM_SESSION_SETUP   = 0x73
	SMB_COM_TREE_CONNECT    = 0x75
	SMB_COM_NT_CREATE_ANDX  = 0xA2
	SMB_COM_WRITE_ANDX      = 0x2F
	SMB_COM_READ_ANDX       = 0x2E
	SMB_COM_CLOSE           = 0x04
	SMB_COM_TREE_DISCONNECT = 0x71
	SMB_COM_LOGOFF          = 0x74
)

// SMB标志和功能
const (
	SMB_FLAGS_CANONICALIZED_PATHS = 0x10
	SMB_FLAGS_CASE_INSENSITIVE    = 0x08
	SMB_FLAGS2_UNICODE            = 0x8000
	SMB_FLAGS2_EXTENDED_SECURITY  = 0x0800

	// 文件创建选项
	FILE_CREATE  = 0x10
	FILE_OPEN    = 0x01
	FILE_OPEN_IF = 0x03

	// 文件共享模式
	FILE_SHARE_READ   = 0x01
	FILE_SHARE_WRITE  = 0x02
	FILE_SHARE_DELETE = 0x04

	// 文件属性
	FILE_ATTRIBUTE_NORMAL = 0x80
)

// SMB头结构
type SMBHeader struct {
	ProtocolID [4]byte
	Command    uint8
	Status     uint32
	Flags      uint8
	Flags2     uint16
	PIDHigh    uint16
	Security   [8]byte
	Reserved   uint16
	TID        uint16
	PIDLow     uint16
	UID        uint16
	MID        uint16
}

// 文件句柄管理
type FileHandle struct {
	FID      uint16
	FilePath string
	File     *os.File
	IsOpen   bool
}

// SMB服务器结构
type SMBServer struct {
	SharePath   string
	NetBIOSName string
	FileHandles map[uint16]*FileHandle
	NextFID     uint16
}

// 创建新的SMB服务器实例
func NewSMBServer(sharePath, netbiosName string) *SMBServer {
	// 确保共享目录存在
	os.MkdirAll(sharePath, 0755)

	return &SMBServer{
		SharePath:   sharePath,
		NetBIOSName: netbiosName,
		FileHandles: make(map[uint16]*FileHandle),
		NextFID:     0x4000, // 从0x4000开始分配FID
	}
}
