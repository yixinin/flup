package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
)

// 处理WRITE_ANDX命令
func (s *SMBServer) handleWriteAndX(conn net.Conn, data []byte) error {
	if len(data) < 40 {
		return errors.New("invalid WRITE_ANDX request")
	}

	// 解析FID和路径
	fid := binary.LittleEndian.Uint16(data[29:31])
	filename, err := s.db.GetFilenameByFID(fid)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_WRITE_ANDX, 0x00060001)
	}

	// 解析写入参数
	dataOffset := int(binary.LittleEndian.Uint16(data[35:37]))
	dataLength := binary.LittleEndian.Uint16(data[33:35])
	writeData := data[dataOffset : dataOffset+int(dataLength)]

	// 使用存储中间件上传文件
	ctx := context.Background()
	err = s.storage.UploadFile(ctx, filename, bytes.NewReader(writeData), int64(dataLength))
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_WRITE_ANDX, 0x00030002)
	}

	// 发送成功响应
	return s.sendWriteResponse(conn, int(dataLength))
}

// 发送写入成功响应
func (s *SMBServer) sendWriteResponse(conn net.Conn, bytesWritten int) error {
	response := make([]byte, 0)

	// NetBIOS会话头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_WRITE_ANDX
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x0C) // 12个字参数

	// 参数块
	params := make([]byte, 24)
	params[0] = 0xFF                                                   // AndXCommand
	binary.LittleEndian.PutUint16(params[2:4], uint16(bytesWritten))   // Count
	binary.LittleEndian.PutUint16(params[4:6], 0)                      // Available
	binary.LittleEndian.PutUint16(params[18:20], uint16(bytesWritten)) // CountHigh

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}
