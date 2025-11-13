package smb

import (
	"encoding/binary"
	"net"
	"time"
)

// 处理SMB协商请求
func (s *SMBServer) handleNegotiate(conn net.Conn, data []byte) error {
	// 构建协商响应
	response := make([]byte, 0)

	// SMB头 (32字节)
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_NEGOTIATE
	// Status = 0 (成功)
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE|SMB_FLAGS2_EXTENDED_SECURITY)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x0D) // 13个字参数

	// 参数块 (13 * 2 = 26字节)
	params := make([]byte, 34)

	// Dialect索引
	binary.LittleEndian.PutUint16(params[0:2], 0)
	// 安全模式
	params[2] = 0x03 // User-level security
	// MaxMpxCount
	binary.LittleEndian.PutUint16(params[3:5], 50)
	// MaxNumberVcs
	binary.LittleEndian.PutUint16(params[5:7], 1)
	// MaxBufferSize
	binary.LittleEndian.PutUint32(params[7:11], 4356)
	// MaxRawSize
	binary.LittleEndian.PutUint32(params[11:15], 65536)
	// SessionKey
	binary.LittleEndian.PutUint32(params[15:19], 0)
	// Capabilities
	binary.LittleEndian.PutUint32(params[19:23], 0)
	// SystemTime
	binary.LittleEndian.PutUint64(params[23:31], uint64(time.Now().UnixNano()))
	// ServerTimeZone
	binary.LittleEndian.PutUint16(params[31:33], 0)
	// ChallengeLength
	params[33] = 0

	response = append(response, params...)

	// ByteCount
	countBs := make([]byte, 2)
	binary.LittleEndian.PutUint16(countBs, uint16(len(s.NetBIOSName)+1))
	response = append(response, countBs...)

	// 服务器名称
	response = append(response, []byte(s.NetBIOSName)...)
	response = append(response, 0) // null终止

	// 设置消息长度
	netbiosHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}
