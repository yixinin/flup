package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// 处理READ_ANDX命令
func (s *SMBServer) handleReadAndX(conn net.Conn, data []byte) error {
	if len(data) < 40 {
		return errors.New("invalid READ_ANDX request")
	}

	// 解析FID
	fid := binary.LittleEndian.Uint16(data[29:31])

	// 从数据库获取文件名
	filename, err := s.db.GetFilenameByFID(fid)
	if err != nil || filename == "" {
		return s.sendErrorResponse(conn, SMB_COM_READ_ANDX, 0x00060001) // 无效句柄
	}

	// 打开文件
	file, err := s.storage.OpenFile(context.Background(), filename)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_READ_ANDX, 0x00030002)
	}

	defer file.Close()

	// 解析读取参数
	offset := binary.LittleEndian.Uint64(data[13:21])
	maxCount := binary.LittleEndian.Uint16(data[33:35])

	// 读取数据
	readBuffer := make([]byte, maxCount)
	bytesRead, err := file.Read(readBuffer)
	if err != nil && err != io.EOF {
		return s.sendErrorResponse(conn, SMB_COM_READ_ANDX, 0x00030002)
	}

	return s.sendReadResponse(conn, readBuffer[offset:bytesRead], bytesRead)
}

// 发送读取成功响应
func (s *SMBServer) sendReadResponse(conn net.Conn, data []byte, bytesRead int) error {
	response := make([]byte, 0)

	// NetBIOS会话头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_READ_ANDX
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x10) // 16个字参数

	// 参数块 (32字节)
	params := make([]byte, 32)

	params[0] = 0xFF                                                // AndXCommand = 无后续命令
	params[1] = 0                                                   // AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0)                   // AndXOffset
	binary.LittleEndian.PutUint16(params[4:6], uint16(bytesRead))   // 读取字节数
	binary.LittleEndian.PutUint16(params[6:8], 0)                   // 可用字节数
	binary.LittleEndian.PutUint32(params[8:12], 0)                  // 数据偏移量
	binary.LittleEndian.PutUint16(params[12:14], uint16(bytesRead)) // 读取字节数(高16位)
	binary.LittleEndian.PutUint16(params[14:16], 0)                 // 可用字节数(高16位)

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], uint16(bytesRead))
	response = response[:len(response)+2]

	// 添加读取的数据
	response = append(response, data...)

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}
