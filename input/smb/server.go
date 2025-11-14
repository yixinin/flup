package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flup/output"
	"flup/storage"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// 处理客户端连接
func (s *SMBServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer s.cleanupFileHandles()

	for {
		// 读取NetBIOS会话头
		var totalRead int
		remaining := 4
		netbiosHeader := make([]byte, 4)

		for remaining > 0 {
			n, err := conn.Read(netbiosHeader[totalRead : totalRead+remaining])
			if err != nil {
				fmt.Printf("Failed to read NetBIOS header: %v\n", err)
				return
			}
			if n == 0 {
				fmt.Println("Unexpected end of connection while reading NetBIOS header")
				return
			}
			totalRead += n
			remaining -= n
		}

		messageLength := binary.BigEndian.Uint32(netbiosHeader)
		if messageLength > 65532 || messageLength == 0 {
			fmt.Printf("Invalid message length: %d\n", messageLength)
			return
		}

		// 完整读取SMB消息
		remaining = int(messageLength)
		smbData := make([]byte, messageLength)
		totalRead = 0

		for remaining > 0 {
			var err error
			n, err := conn.Read(smbData[totalRead : totalRead+remaining])
			if err != nil {
				fmt.Printf("Failed to read SMB message: %v\n", err)
				return
			}
			if n == 0 {
				fmt.Println("Unexpected end of connection while reading SMB message")
				return
			}
			totalRead += n
			remaining -= n
		}

		// 验证SMB协议头
		if len(smbData) < 4 || smbData[0] != 0xFF || smbData[1] != 'S' || smbData[2] != 'M' || smbData[3] != 'B' {
			fmt.Println("Invalid SMB protocol header")
			return
		}

		command := smbData[4]

		fmt.Printf("handleNegotiate data: %s\n", smbData)
		fmt.Println(conn.RemoteAddr().String(), "command:", command)

		data := smbData[:totalRead]
		var handleErr error
		switch command {
		case SMB_COM_NEGOTIATE:
			handleErr = s.handleNegotiate(conn, data)
		case SMB_COM_SESSION_SETUP:
			handleErr = s.handleSessionSetup(conn, data)
		case SMB_COM_TREE_CONNECT:
			handleErr = s.handleTreeConnect(conn, data)
		case SMB_COM_NT_CREATE_ANDX:
			handleErr = s.handleNTCreateAndX(conn, data)
		case SMB_COM_WRITE_ANDX:
			handleErr = s.handleWriteAndX(conn, data)
		case SMB_COM_READ_ANDX:
			handleErr = s.handleReadAndX(conn, data)
		case 0x0F: // SMB_COM_FIND_FIRST2
			handleErr = s.handleFindFirst2(conn, data)
		case SMB_COM_CLOSE:
			handleErr = s.handleClose(conn, data)
		case SMB_COM_TREE_DISCONNECT:
			handleErr = s.handleTreeDisconnect(conn, data)
		case SMB_COM_LOGOFF:
			handleErr = s.handleLogoff(conn, data)
		default:
			fmt.Printf("Unsupported SMB command: 0x%02X\n", command)
			handleErr = s.sendErrorResponse(conn, command, 0x00010001) // 不支持的命令
		}

		if handleErr != nil {
			fmt.Printf("Error handling command 0x%02X: %v\n", command, handleErr)
		}
	}
}

// 会话建立处理
func (s *SMBServer) handleSessionSetup(conn net.Conn, data []byte) error {
	// 生成随机UID
	uid := uint16(1) // 在实际实现中应该使用动态分配

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
	smbHeader[4] = SMB_COM_SESSION_SETUP
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)
	binary.LittleEndian.PutUint16(smbHeader[26:28], uid) // 设置UID

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x07) // 7个字参数

	// 参数块 (14字节)
	params := make([]byte, 14)
	binary.LittleEndian.PutUint16(params[0:2], 0x0000)      // 错误等级
	binary.LittleEndian.PutUint16(params[2:4], 0x0000)      // Action
	binary.LittleEndian.PutUint16(params[4:6], uid)         // UID
	binary.LittleEndian.PutUint32(params[6:10], 0x00000000) // 会话密钥
	binary.LittleEndian.PutUint16(params[10:12], 0x0000)    // 模拟级别
	binary.LittleEndian.PutUint16(params[12:14], 0x0000)    // 最大缓冲区大小

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0x0000)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
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

	// 提取共享名称（处理Unicode）
	var shareName string
	flags2 := binary.LittleEndian.Uint16(data[10:12])
	if flags2&SMB_FLAGS2_UNICODE != 0 {
		// UTF-16LE编码，寻找双字节null终止符
		nullIndex := -1
		for i := shareNameOffset; i < len(data)-1; i += 2 {
			if data[i] == 0 && data[i+1] == 0 {
				nullIndex = i
				break
			}
		}
		if nullIndex == -1 {
			return s.sendErrorResponse(conn, SMB_COM_TREE_CONNECT, 0x00020002)
		}
		// 转换UTF-16LE到字符串
		utf16Bytes := data[shareNameOffset:nullIndex]
		// 将字节转换为uint16切片
		utf16Str := make([]uint16, len(utf16Bytes)/2)
		for i := 0; i < len(utf16Str); i++ {
			utf16Str[i] = binary.LittleEndian.Uint16(utf16Bytes[i*2:])
		}
		shareName = string(utf16.Decode(utf16Str))
	} else {
		// ASCII编码
		nullIndex := bytes.IndexByte(data[shareNameOffset:], 0)
		if nullIndex == -1 {
			return s.sendErrorResponse(conn, SMB_COM_TREE_CONNECT, 0x00020002)
		}
		shareName = string(data[shareNameOffset : shareNameOffset+nullIndex])
	}

	// 验证共享名称 (格式: \server\share)
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
	response = append(response, 0, 0)                                 // 为ByteCount预留空间
	binary.LittleEndian.PutUint16(response[len(response)-2:], 0x0044) // 68字节数据

	// 响应数据 (68字节)
	dataBytes := make([]byte, 68)
	// 填充支持的方言列表
	copy(dataBytes[0:18], []byte("SMB 2.100\x00"))   // SMB 2.1
	copy(dataBytes[18:34], []byte("SMB 2.002\x00"))  // SMB 2.0
	copy(dataBytes[34:50], []byte("SMB 1.002\x00"))  // SMB 1.0
	copy(dataBytes[50:66], []byte("NT LM 0.12\x00")) // NT LM 0.12
	dataBytes[66] = 0x00
	dataBytes[67] = 0x00

	response = append(response, dataBytes...)

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

	// 从数据库获取文件名
	filename, err := s.db.GetFilenameByFID(fid)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_CLOSE, 0x00060001) // 无效句柄
	}

	// 删除FID映射
	if err := s.db.DeleteFIDMapping(fid, filename); err != nil {
		return s.sendErrorResponse(conn, SMB_COM_CLOSE, 0x00060001)
	}

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

// SMBServer SMB服务器结构体

type SMBServer struct {
	// db          *persist
	db          *storage.Database
	PathPrefix  string
	NetBIOSName string
	mutex       sync.Mutex
	storage     output.BackendStorage // 添加存储后端接口
}

// NewSMBServer 创建SMB服务器实例
func NewSMBServer(netBIOSName string, db *storage.Database, storage output.BackendStorage) *SMBServer {
	return &SMBServer{
		db:          db,
		NetBIOSName: netBIOSName,
		storage:     storage, // 使用本地文件系统存储后端
	}
}

// 清理文件句柄
func (s *SMBServer) cleanupFileHandles() {
	// 不再需要清理FileHandles，由Badger管理
}

// 协议协商处理
func (s *SMBServer) handleNegotiate(conn net.Conn, data []byte) error {
	// 验证SMB协议头
	if len(data) < 4 || data[0] != 0xFF || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		return s.sendErrorResponse(conn, SMB_COM_NEGOTIATE, 0x00010002)
	}

	// 检查数据长度是否满足最小要求
	if len(data) < 32+1 { // SMB头(32) + WordCount(1)
		fmt.Println("handleNegotiate data too short for header")
		return s.sendErrorResponse(conn, SMB_COM_NEGOTIATE, 0x00010002)
	}

	wordCount := int(data[32])
	byteCount := int(binary.LittleEndian.Uint16(data[33:35]))

	// 计算方言数据起始位置
	dialectDataStart := 35 + wordCount*2

	// 验证数据长度
	if len(data) < dialectDataStart+byteCount {
		fmt.Printf("handleNegotiate data len %d < required %d\n", len(data), dialectDataStart+byteCount)
		return s.sendErrorResponse(conn, SMB_COM_NEGOTIATE, 0x00010002)
	}

	// 提取客户端方言列表
	clientDialects := []string{}
	dialectData := data[dialectDataStart : dialectDataStart+byteCount]

	// 解析方言列表 (以0x02开头，0x00结尾的UTF-8字符串)
	currentPos := 0
	for currentPos < len(dialectData) {
		// 查找方言起始标记0x02
		if dialectData[currentPos] != 0x02 {
			currentPos++
			continue
		}
		currentPos++ // 跳过0x02标记

		// 查找方言结束标记0x00
		endPos := currentPos
		for endPos < len(dialectData) && dialectData[endPos] != 0x00 {
			endPos++
		}

		if endPos >= len(dialectData) {
			break // 未找到结束标记，终止解析
		}

		// 提取并转换UTF-8方言字符串
		if endPos > currentPos {
			clientDialects = append(clientDialects, string(dialectData[currentPos:endPos]))
		}

		currentPos = endPos + 1 // 移动到下一个可能的起始标记
	}

	// 选择支持的方言
	selectedDialect := ""
	selectedDialectIndex := 0
	supportedDialects := []string{"NT LM 0.12", "SMB 2.002", "LANMAN2.1", "LM1.2X002"}
	for _, dialect := range supportedDialects {
		for i, clientDialect := range clientDialects {
			if dialect == clientDialect {
				selectedDialect = dialect
				selectedDialectIndex = i
				break
			}
		}
		if selectedDialect != "" {
			break
		}
	}

	if selectedDialect == "" {
		fmt.Printf("handleNegotiate no supported dialect found. Client dialects: %v\n", clientDialects)
		return s.sendErrorResponse(conn, SMB_COM_NEGOTIATE, 0x00020002)
	}

	// 构建协商响应
	response := &SMBHeader{
		Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
		Command:  SMB_COM_NEGOTIATE,
		Status:   0,
		Flags:    0x18,
	}

	// 响应参数
	var paramWords []uint16
	paramWords = append(paramWords, uint16(selectedDialectIndex)) // 方言索引
	paramWords = append(paramWords, 0x0000)                       // 安全模式
	paramWords = append(paramWords, 0x0000)                       // 最大MUX计数
	paramWords = append(paramWords, 0x0000)                       // 最大消息大小
	paramWords = append(paramWords, 0x0000)                       // 最大传输单元

	// 响应数据
	// 预分配足够容量减少内存分配: GUID(16) + 安全模式(2) + 服务器时间(8) + 方言长度 + 终止符(1)
	estimatedSize := 16 + 2 + 8 + len(selectedDialect) + 1
	dataBytes := make([]byte, 0, estimatedSize)

	// 服务器GUID
	guid := make([]byte, 16)
	rand.Read(guid)
	dataBytes = append(dataBytes, guid...)

	// 支持的安全模式
	dataBytes = append(dataBytes, 0x01, 0x00) // 只支持NTLMSSP

	// 服务器时间
	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(time.Now().UnixNano()/100))
	dataBytes = append(dataBytes, timeBytes...)

	// 使用UTF-8编码选择的方言
	dataBytes = append(dataBytes, []byte(selectedDialect)...)
	dataBytes = append(dataBytes, 0x00) // UTF-8空终止符

	// 构建SMB消息
	response.WordCount = uint8(len(paramWords))
	response.ByteCount = uint16(len(dataBytes))

	// 序列化响应
	buf := &bytes.Buffer{}
	response.Serialize(buf)
	for _, word := range paramWords {
		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, word)
		buf.Write(data)
	}
	buf.Write(dataBytes)

	// 添加NetBIOS头
	netbiosHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(netbiosHeader, uint32(buf.Len()))
	fullResponse := append(netbiosHeader, buf.Bytes()...)

	// 发送响应
	n, err := conn.Write(fullResponse)
	if err != nil || n != len(fullResponse) {
		return fmt.Errorf("failed to send negotiate response: %v", err)
	}
	fmt.Printf("handleNegotiate response: %s\n", fullResponse)
	return nil
}
