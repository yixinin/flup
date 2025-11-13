package smb

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// 处理NT_CREATE_ANDX命令
func (s *SMBServer) handleNTCreateAndX(conn net.Conn, data []byte) error {
	if len(data) < 40 {
		return errors.New("invalid NT_CREATE_ANDX request")
	}

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

	// 解析创建选项
	// createOptions := binary.LittleEndian.Uint32(data[25:29])
	createDisposition := binary.LittleEndian.Uint32(data[29:33])

	// 构建完整的本地文件路径
	localPath := filepath.Join(s.SharePath, fileName)

	// 确保目录存在
	os.MkdirAll(filepath.Dir(localPath), 0755)

	// 处理创建选项
	var file *os.File
	var err error

	switch createDisposition {
	case FILE_CREATE: // 创建新文件
		file, err = os.Create(localPath)
	case FILE_OPEN: // 打开现有文件
		file, err = os.OpenFile(localPath, os.O_RDWR, 0644)
	case FILE_OPEN_IF: // 打开或创建
		if _, err := os.Stat(localPath); os.IsNotExist(err) {
			file, err = os.Create(localPath)
		} else {
			file, err = os.OpenFile(localPath, os.O_RDWR, 0644)
		}
	default:
		file, err = os.Create(localPath)
	}

	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_NT_CREATE_ANDX, 0x00020002) // 访问被拒绝
	}

	// 分配文件句柄
	fid := s.NextFID
	s.NextFID++

	s.FileHandles[fid] = &FileHandle{
		FID:      fid,
		FilePath: localPath,
		File:     file,
		IsOpen:   true,
	}

	return s.sendCreateResponse(conn, fid, localPath)
}

// 发送文件创建成功响应
func (s *SMBServer) sendCreateResponse(conn net.Conn, fid uint16, filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_NT_CREATE_ANDX, 0x00000005)
	}

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
	binary.LittleEndian.PutUint64(params[28:36], uint64(fileInfo.Size()))
	// 文件权限
	binary.LittleEndian.PutUint32(params[36:40], 0x0012019F)

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err = conn.Write(append(netbiosHeader, response...))
	return err
}
