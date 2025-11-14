package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// 处理NT_CREATE_ANDX命令
func (s *SMBServer) handleNTCreateAndX(conn net.Conn, data []byte) error {
	if len(data) < 40 {
		return errors.New("invalid NT_CREATE_ANDX request")
	}

	// 解析文件属性判断是否为目录
	fileAttributes := binary.LittleEndian.Uint32(data[20:24])
	isDir := (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0

	// 解析文件名偏移量
	fileNameOffset := int(binary.LittleEndian.Uint16(data[33:35]))
	if fileNameOffset >= len(data) {
		return errors.New("invalid file name offset")
	}

	// 提取文件名
	var fileNameBuilder strings.Builder
	for i := fileNameOffset; i < len(data) && data[i] != 0; i++ {
		fileNameBuilder.WriteByte(data[i])
	}
	fileName := fileNameBuilder.String()
	fullPath := fmt.Sprintf("%s/%s", s.PathPrefix, fileName)

	// 根据类型调用存储后端创建方法
	ctx := context.Background()
	var err error
	if isDir {
		err = s.storage.CreateDir(ctx, fullPath)
	} else {
		err = s.storage.CreateFile(ctx, fullPath)
	}
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_NT_CREATE_ANDX, 0x00020002) // 访问被拒绝
	}

	// 使用Badger生成唯一FID
	fid, err := s.db.GenerateFID()
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_NT_CREATE_ANDX, 0x00020002)
	}

	// 存储FID与文件名的映射关系
	if err := s.db.StoreFIDMapping(fid, fileName); err != nil {
		return s.sendErrorResponse(conn, SMB_COM_NT_CREATE_ANDX, 0x00020002)
	}

	return s.sendCreateResponse(conn, fid, fullPath)
}

// 发送文件创建成功响应
func (s *SMBServer) sendCreateResponse(conn net.Conn, fid uint16, filePath string) error {
	response := make([]byte, 0)
	// NetBIOS会话头 (4字节)
	netbiosHeader := make([]byte, 4)

	// SMB头 (32字节)
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_NT_CREATE_ANDX
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x2A) // 42个字参数

	// 参数块 (84字节)
	params := make([]byte, 84)

	// 创建操作结果
	params[0] = 0xFF                              // AndXCommand = 无后续命令
	params[1] = 0                                 // AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0) // AndXOffset

	// OpLock级别
	params[4] = 0
	// FID
	binary.LittleEndian.PutUint16(params[6:8], fid)
	// 创建动作
	binary.LittleEndian.PutUint32(params[8:12], FILE_CREATE)
	// 文件属性
	binary.LittleEndian.PutUint32(params[20:24], FILE_ATTRIBUTE_NORMAL)
	// 文件大小
	binary.LittleEndian.PutUint64(params[28:36], uint64(0))
	// 文件权限
	binary.LittleEndian.PutUint32(params[36:40], 0x0012019F)

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}
