package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// 处理客户端连接
func (s *SMBServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer s.cleanupFileHandles()

	buffer := make([]byte, 65536)

	for {
		// 读取NetBIOS会话头
		n, err := conn.Read(buffer[:4])
		if err != nil || n != 4 {
			fmt.Printf("Failed to read NetBIOS header: %v\n", err)
			return
		}

		messageLength := binary.BigEndian.Uint32(buffer[:4])
		if messageLength > 65532 {
			fmt.Printf("Message too large: %d\n", messageLength)
			return
		}

		// 读取SMB消息
		n, err = conn.Read(buffer[:messageLength])
		if err != nil || n != int(messageLength) {
			fmt.Printf("Failed to read SMB message: %v\n", err)
			return
		}

		// 验证SMB协议头
		if buffer[0] != 0xFF || buffer[1] != 'S' || buffer[2] != 'M' || buffer[3] != 'B' {
			fmt.Println("Invalid SMB protocol header")
			return
		}

		command := buffer[4]

		fmt.Println(conn.RemoteAddr().String(), "command:", command)

		var handleErr error
		switch command {
		case SMB_COM_NEGOTIATE:
			handleErr = s.handleNegotiate(conn, buffer[:n])
		case SMB_COM_SESSION_SETUP:
			handleErr = s.handleSessionSetup(conn, buffer[:n])
		case SMB_COM_TREE_CONNECT:
			handleErr = s.handleTreeConnect(conn, buffer[:n])
		case SMB_COM_NT_CREATE_ANDX:
			handleErr = s.handleNTCreateAndX(conn, buffer[:n])
		case SMB_COM_WRITE_ANDX:
			handleErr = s.handleWriteAndX(conn, buffer[:n])
		case SMB_COM_READ_ANDX:
			handleErr = s.handleReadAndX(conn, buffer[:n])
		case 0x0F: // SMB_COM_FIND_FIRST2
			handleErr = s.handleFindFirst2(conn, buffer[:n])
		case SMB_COM_CLOSE:
			handleErr = s.handleClose(conn, buffer[:n])
		case SMB_COM_TREE_DISCONNECT:
			handleErr = s.handleTreeDisconnect(conn, buffer[:n])
		case SMB_COM_LOGOFF:
			handleErr = s.handleLogoff(conn, buffer[:n])
		default:
			fmt.Printf("Unsupported SMB command: 0x%02X\n", command)
			handleErr = s.sendErrorResponse(conn, command, 0x00010001) // 不支持的命令
		}

		if handleErr != nil {
			fmt.Printf("Error handling command 0x%02X: %v\n", command, handleErr)
		}
	}
}

// 清理文件句柄
func (s *SMBServer) cleanupFileHandles() {
	for fid, fileHandle := range s.FileHandles {
		if fileHandle.IsOpen {
			fileHandle.File.Close()
		}
		delete(s.FileHandles, fid)
	}
}

// 会话建立处理（简化版）
func (s *SMBServer) handleSessionSetup(conn net.Conn, data []byte) error {
	// 发送简单的成功响应
	return s.sendSuccessResponse(conn, SMB_COM_SESSION_SETUP)
}

// 树连接处理
func (s *SMBServer) handleTreeConnect(conn net.Conn, data []byte) error {
	if len(data) < 36 {
		return s.sendErrorResponse(conn, SMB_COM_TREE_CONNECT, 0x00020002)
	}

	// 解析共享名称偏移量
	shareNameOffset := int(binary.LittleEndian.Uint16(data[34:36]))
	if shareNameOffset >= len(data) {
		return s.sendErrorResponse(conn, SMB_COM_TREE_CONNECT, 0x00020002)
	}

	// 提取共享名称
	nullIndex := bytes.IndexByte(data[shareNameOffset:], 0)
	if nullIndex == -1 {
		return s.sendErrorResponse(conn, SMB_COM_TREE_CONNECT, 0x00020002)
	}
	shareName := string(data[shareNameOffset : shareNameOffset+nullIndex])

	// 验证共享名称 (格式: \\server\share)
	parts := strings.Split(shareName, "\\")
	if len(parts) < 3 || parts[2] != "smbshare" {
		return s.sendErrorResponse(conn, SMB_COM_TREE_CONNECT, 0x00020002)
	}

	// 分配TID
	tid := uint16(1) // 在实际实现中应该使用动态分配

	// 构建响应
	response := make([]byte, 0)

	// NetBIOS会话头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_TREE_CONNECT
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)
	binary.LittleEndian.PutUint16(smbHeader[24:26], tid) // 设置TID

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x04) // 4个字参数

	// 参数块 (8字节)
	params := make([]byte, 8)
	binary.LittleEndian.PutUint16(params[0:2], 0x0000)     // OptionalSupport
	binary.LittleEndian.PutUint32(params[2:6], 0x00000000) // MaximalAccessRights
	binary.LittleEndian.PutUint16(params[6:8], 0x0000)     // GuestMaximalAccessRights

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}

// 树断开处理
func (s *SMBServer) handleTreeDisconnect(conn net.Conn, data []byte) error {
	return s.sendSuccessResponse(conn, SMB_COM_TREE_DISCONNECT)
}

// 注销处理
func (s *SMBServer) handleLogoff(conn net.Conn, data []byte) error {
	s.cleanupFileHandles()
	return s.sendSuccessResponse(conn, SMB_COM_LOGOFF)
}

// 发送成功响应（通用）
func (s *SMBServer) sendSuccessResponse(conn net.Conn, command uint8) error {
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
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0) // 0个字参数

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}

// 关闭文件处理
func (s *SMBServer) handleClose(conn net.Conn, data []byte) error {
	if len(data) < 32 {
		return errors.New("invalid CLOSE request")
	}

	// 解析FID
	fid := binary.LittleEndian.Uint16(data[29:31])

	// 查找并关闭文件句柄
	fileHandle, exists := s.FileHandles[fid]
	if !exists || !fileHandle.IsOpen {
		return s.sendErrorResponse(conn, SMB_COM_CLOSE, 0x00060001) // 无效句柄
	}

	// 关闭文件
	fileHandle.File.Close()
	fileHandle.IsOpen = false
	delete(s.FileHandles, fid)

	return s.sendCloseResponse(conn)
}

// 发送关闭成功响应
func (s *SMBServer) sendCloseResponse(conn net.Conn) error {
	response := make([]byte, 0)

	// NetBIOS会话头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_CLOSE
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x08) // 8个字参数

	// 参数块 (16字节)
	params := make([]byte, 16)
	binary.LittleEndian.PutUint16(params[0:2], 0)   // Reserved
	binary.LittleEndian.PutUint32(params[2:6], 0)   // CreationTime
	binary.LittleEndian.PutUint32(params[6:10], 0)  // LastAccessTime
	binary.LittleEndian.PutUint32(params[10:14], 0) // LastWriteTime
	binary.LittleEndian.PutUint32(params[14:18], 0) // LastChangeTime

	response = append(response, params[:16]...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}
