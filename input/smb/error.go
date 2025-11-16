package smb

import (
	"encoding/binary"
	"errors"
	"net"
)

// 发送错误响应
func (s *SMBServer) sendErrorResponse(conn net.Conn, command uint8, status uint32) error {
	response := make([]byte, 0)

	// NetBIOS会话头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = command
	binary.LittleEndian.PutUint32(smbHeader[5:9], status)
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0) // 错误响应没有参数

	// ByteCount
	byteCount := make([]byte, 2)
	binary.LittleEndian.PutUint16(byteCount, 0)
	response = append(response, byteCount...)

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}

// 解析SMB头
func parseSMBHeader(data []byte) (*SMBHeader, error) {
	if len(data) < 32 {
		return nil, errors.New("invalid SMB header length")
	}

	if data[0] != 0xFF || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		return nil, errors.New("invalid SMB protocol signature")
	}

	header := &SMBHeader{
		Command: data[4],
		Status:  binary.LittleEndian.Uint32(data[5:9]),
		Flags:   data[9],
		Flags2:  binary.LittleEndian.Uint16(data[10:12]),
		PIDHigh: binary.LittleEndian.Uint16(data[12:14]),
		TID:     binary.LittleEndian.Uint16(data[24:26]),
		PIDLow:  binary.LittleEndian.Uint16(data[26:28]),
		UID:     binary.LittleEndian.Uint16(data[28:30]),
		MID:     binary.LittleEndian.Uint16(data[30:32]),
	}
	copy(header.Protocol[:], data[0:4])
	copy(header.Security[:], data[14:22])

	return header, nil
}
