package smb

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flup/output"
	"flup/storage"
	"fmt"
	"net"
	"strconv"
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
		case SMB_COM_FIND_FIRST2:
			handleErr = s.handleFindFirst2(conn, data)
		case SMB_COM_FIND_NEXT2:
			handleErr = s.handleFindNext2(conn, data)
		case SMB_COM_ECHO:
			handleErr = s.handleEcho(conn, data)
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
	// 检查NTLMSSP协商
	if len(data) > 40 && string(data[14:22]) == string(NTLMSSP_SIGNATURE[:]) {
		messageType := binary.LittleEndian.Uint32(data[24:28])

		switch messageType {
		case NTLM_MESSAGE_TYPE_NEGOTIATE:
			// 发送Challenge消息
			return s.sendNTLMChallenge(conn)
		case NTLM_MESSAGE_TYPE_AUTHENTICATE:
			// 验证认证消息
			return s.verifyNTLMAuthenticate(conn, data)
		default:
			return s.sendErrorResponse(conn, SMB_COM_SESSION_SETUP, 0x00060001)
		}
	}

	// 传统认证（保留向后兼容）
	s.mutex.Lock()
	uid := s.nextUID
	s.nextUID++
	s.mutex.Unlock()

	// 构建响应
	response := make([]byte, 0)

	// NetBIOS会话头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := makeSMBHeader(SMB_COM_SESSION_SETUP, 0)
	binary.LittleEndian.PutUint16(smbHeader[26:28], uid)

	// 构建响应
	response = append(smbHeader, []byte{0x01, 0x00}...)                                // WordCount
	response = append(response, binary.LittleEndian.AppendUint16([]byte{}, 0x0000)...) // 状态码
	response = append(response, binary.LittleEndian.AppendUint16([]byte{}, uid)...)    // UID
	response = append(response, make([]byte, 8)...)                                    // 保留字段
	binary.LittleEndian.PutUint16(response[len(response)-2:], 0)                       // ByteCount

	// 设置NetBIOS长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))
	response = append(netbiosHeader, response...)
	_, err := conn.Write(response)
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
	s.mutex.Lock()
	tid := s.nextTID
	s.nextTID++
	s.mutex.Unlock()

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

	// 响应数据 (68字节)
	dataBytes := make([]byte, 68)
	// ByteCount
	response = append(response, 0, 0)                                                 // 为ByteCount预留空间
	binary.LittleEndian.PutUint16(response[len(response)-2:], uint16(len(dataBytes))) // 使用实际数据长度

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
	db                  *storage.Database
	PathPrefix          string
	NetBIOSName         string
	mutex               sync.Mutex
	storage             output.BackendStorage // 添加存储后端接口
	nextUID             uint16
	nextTID             uint16
	nextSearchID        uint16
	searchMutex         sync.Mutex
	searchContinuations map[uint16]SearchState
	lockMutex           sync.Mutex
	fileLocks           map[uint16][]LockInfo // FID -> 锁列表
	udpConns            map[int]*net.UDPConn  // 存储多个UDP连接
	udpPorts            []int                 // 监听的UDP端口列表
}

// 锁信息
type LockInfo struct {
	Offset uint64
	Length uint64
	Type   uint32 // 0: 共享锁, 1: 排他锁
	UID    uint16
}

// 搜索状态
type SearchState struct {
	Entries []output.FileInfo
	Index   int
}

// NewSMBServer 创建SMB服务器实例
func NewSMBServer(netBIOSName string, db *storage.Database, storage output.BackendStorage) *SMBServer {
	return &SMBServer{
		NetBIOSName:         netBIOSName,
		db:                  db,
		storage:             storage,
		nextUID:             1000,
		nextTID:             1000,
		searchContinuations: make(map[uint16]SearchState),
		lockMutex:           sync.Mutex{},
		fileLocks:           make(map[uint16][]LockInfo), // FID -> 锁列表
		udpPorts:            []int{137, 138, 139},
		udpConns:            make(map[int]*net.UDPConn), // 初始化UDP连接map
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

// ECHO命令处理
func (s *SMBServer) handleEcho(conn net.Conn, data []byte) error {
	return s.sendEchoResponse(conn)
}

// 发送ECHO响应
func (s *SMBServer) sendEchoResponse(conn net.Conn) error {
	response := make([]byte, 0)

	// NetBIOS会话头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_ECHO
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x01) // 1个字参数

	// 参数块 (2字节)
	params := make([]byte, 2)
	binary.LittleEndian.PutUint16(params, 0x0000) // 回显成功

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0x0000)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}

// LOCK命令处理
func (s *SMBServer) handleLock(conn net.Conn, data []byte) error {
	if len(data) < 48 {
		return errors.New("invalid LOCK request")
	}

	// 解析参数
	fid := binary.LittleEndian.Uint16(data[29:31])
	uid := binary.LittleEndian.Uint16(data[28:30])
	offset := binary.LittleEndian.Uint64(data[33:41])
	length := binary.LittleEndian.Uint64(data[41:49])
	lockType := binary.LittleEndian.Uint32(data[49:53])

	// 验证文件是否存在
	_, err := s.db.GetFilenameByFID(fid)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_LOCK, 0x00060001)
	}

	// 检查锁冲突
	s.lockMutex.Lock()
	defer s.lockMutex.Unlock()

	if s.fileLocks == nil {
		s.fileLocks = make(map[uint16][]LockInfo)
	}

	locks := s.fileLocks[fid]
	for _, lock := range locks {
		// 检查是否重叠
		if !(offset+length <= lock.Offset || offset >= lock.Offset+lock.Length) {
			// 存在重叠
			if lockType == 1 || lock.Type == 1 {
				// 排他锁冲突
				return s.sendErrorResponse(conn, SMB_COM_LOCK, 0x00020001)
			}
		}
	}

	// 添加新锁
	newLock := LockInfo{
		Offset: offset,
		Length: length,
		Type:   lockType,
		UID:    uid,
	}
	locks = append(locks, newLock)
	s.fileLocks[fid] = locks

	return s.sendLockResponse(conn, true)
}

// UNLOCK命令处理
func (s *SMBServer) handleUnlock(conn net.Conn, data []byte) error {
	if len(data) < 48 {
		return errors.New("invalid UNLOCK request")
	}

	// 解析参数
	fid := binary.LittleEndian.Uint16(data[29:31])
	offset := binary.LittleEndian.Uint64(data[33:41])
	length := binary.LittleEndian.Uint64(data[41:49])

	// 验证文件是否存在
	_, err := s.db.GetFilenameByFID(fid)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_UNLOCK, 0x00060001)
	}

	// 查找并删除锁
	s.lockMutex.Lock()
	defer s.lockMutex.Unlock()

	locks, exists := s.fileLocks[fid]
	if !exists {
		return s.sendErrorResponse(conn, SMB_COM_UNLOCK, 0x00060001)
	}

	newLocks := []LockInfo{}
	found := false
	for _, lock := range locks {
		if lock.Offset == offset && lock.Length == length {
			found = true
			continue
		}
		newLocks = append(newLocks, lock)
	}

	if !found {
		return s.sendErrorResponse(conn, SMB_COM_UNLOCK, 0x00060001)
	}

	s.fileLocks[fid] = newLocks
	if len(newLocks) == 0 {
		delete(s.fileLocks, fid)
	}

	return s.sendUnlockResponse(conn, true)
}

// 发送LOCK响应
func (s *SMBServer) sendLockResponse(conn net.Conn, success bool) error {
	// 构建响应...
	return s.sendGenericResponse(conn, SMB_COM_LOCK, success)
}

// 发送UNLOCK响应
func (s *SMBServer) sendUnlockResponse(conn net.Conn, success bool) error {
	// 构建响应...
	return s.sendGenericResponse(conn, SMB_COM_UNLOCK, success)
}

// 发送通用成功响应
func (s *SMBServer) sendGenericResponse(conn net.Conn, command uint8, success bool) error {
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
	if !success {
		binary.LittleEndian.PutUint32(smbHeader[5:9], 0x00020001) // 操作失败
	}
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x01) // 1个字参数

	// 参数块 (2字节)
	params := make([]byte, 2)
	binary.LittleEndian.PutUint16(params, 0x0000)

	response = append(response, params...)

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], 0x0000)
	response = response[:len(response)+2]

	// 设置NetBIOS消息长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}

// DELETE命令处理
func (s *SMBServer) handleDelete(conn net.Conn, data []byte) error {
	if len(data) < 31 {
		return errors.New("invalid DELETE request")
	}

	fid := binary.LittleEndian.Uint16(data[29:31])

	// 获取文件名
	filename, err := s.db.GetFilenameByFID(fid)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_DELETE, 0x00060001)
	}

	// 删除文件
	if err := s.storage.Delete(context.Background(), []string{filename}, false); err != nil {
		return s.sendErrorResponse(conn, SMB_COM_DELETE, 0x00060003)
	}

	// 从数据库中移除FID映射
	s.db.RemoveFID(fid)

	return s.sendGenericResponse(conn, SMB_COM_DELETE, true)
}

// RENAME命令处理
func (s *SMBServer) handleRename(conn net.Conn, data []byte) error {
	if len(data) < 64 {
		return errors.New("invalid RENAME request")
	}

	fid := binary.LittleEndian.Uint16(data[29:31])
	newNameLen := int(binary.LittleEndian.Uint16(data[33:35]))
	newNameOffset := int(binary.LittleEndian.Uint16(data[35:37]))

	if newNameOffset+newNameLen > len(data) {
		return errors.New("invalid new name in RENAME request")
	}

	newName := string(data[newNameOffset : newNameOffset+newNameLen])

	// 获取旧文件名
	oldName, err := s.db.GetFilenameByFID(fid)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_RENAME, 0x00060001)
	}

	// 重命名文件
	if err := s.storage.Rename(context.Background(), oldName, newName); err != nil {
		return s.sendErrorResponse(conn, SMB_COM_RENAME, 0x00060004)
	}

	// 更新数据库中的文件名
	s.db.UpdateFilenameByFID(fid, newName)

	return s.sendGenericResponse(conn, SMB_COM_RENAME, true)
}

var NTLMSSP_SIGNATURE = [8]byte{
	'N',
	'T',
	'L',
	'M',
	'S',
	'S',
	'P',
	'\x00',
} //("NTLMSSP\x00")
const (
	NTLM_MESSAGE_TYPE_NEGOTIATE    = 1
	NTLM_MESSAGE_TYPE_CHALLENGE    = 2
	NTLM_MESSAGE_TYPE_AUTHENTICATE = 3
)

// NTLM Negotiate消息结构
type NTLMNegotiate struct {
	Signature      [8]byte
	MessageType    uint32
	NegotiateFlags uint32
}

// NTLM Challenge消息结构
type NTLMChallenge struct {
	Signature        [8]byte
	MessageType      uint32
	TargetNameFields [8]byte
	NegotiateFlags   uint32
	ServerChallenge  [8]byte
	Reserved         [8]byte
	TargetInfoFields [8]byte
}

// 发送NTLM Challenge消息
func (s *SMBServer) sendNTLMChallenge(conn net.Conn) error {
	challenge := NTLMChallenge{
		Signature:      NTLMSSP_SIGNATURE,
		MessageType:    NTLM_MESSAGE_TYPE_CHALLENGE,
		NegotiateFlags: 0x20080207,
	}
	// 生成随机Challenge
	_, err := rand.Read(challenge.ServerChallenge[:])
	if err != nil {
		return fmt.Errorf("生成随机Challenge失败: %v", err)
	}

	// 构建SMB响应
	smbHeader := makeSMBHeader(SMB_COM_SESSION_SETUP, 0)
	response := append(smbHeader, []byte{0x01, 0x00}...)
	response = append(response, binary.LittleEndian.AppendUint16([]byte{}, 0xFFF7)...) // 状态码: 需要更多数据
	response = append(response, []byte{0x00, 0x00, 0x00, 0x00}...)                     // 安全缓冲区偏移和长度

	// 添加NTLM Challenge数据
	challengeBytes := make([]byte, 40)
	copy(challengeBytes[:8], challenge.Signature[:])
	binary.LittleEndian.PutUint32(challengeBytes[8:12], challenge.MessageType)
	binary.LittleEndian.PutUint32(challengeBytes[20:24], challenge.NegotiateFlags)
	copy(challengeBytes[24:32], challenge.ServerChallenge[:])

	response = append(response, challengeBytes...)

	// 添加NetBIOS头
	netbiosHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))
	response = append(netbiosHeader, response...)

	_, err = conn.Write(response)
	return err
}

// 验证NTLM Authenticate消息
func (s *SMBServer) verifyNTLMAuthenticate(conn net.Conn, data []byte) error {
	// 简化实现：实际应验证NTLM哈希
	// 这里仅检查消息结构并分配UID
	s.mutex.Lock()
	uid := s.nextUID
	s.nextUID++
	s.mutex.Unlock()

	// 发送成功响应
	response := createSessionSetupResponse(uid)
	_, err := conn.Write(response)
	return err
}

// 检查是否是NetBIOS发现请求
func isNetBIOSDiscoveryRequest(data []byte) bool {
	// 简单检查NetBIOS名称查询请求格式
	return len(data) >= 12 && data[0] == 0x00 && data[1] == 0x00 &&
		data[2] == 0x00 && data[3] == 0x00 &&
		data[4] == 0x00 && data[5] == 0x01 &&
		bytes.Equal(data[12:15], []byte{0x20, 0x43, 0x4B})
}

// 创建NetBIOS发现响应
func createNetBIOSDiscoveryResponse(serverName string) []byte {
	// 构建简化的NetBIOS响应包
	response := make([]byte, 50)
	response[0] = 0x84                      // 响应标志
	response[1] = 0x00                      // 错误码
	copy(response[12:], []byte(serverName)) // 服务器名称
	// 添加IP地址和端口信息
	return response
}

// StartUDPServers 启动所有UDP服务器
func (s *SMBServer) StartUDPServers() error {
	for _, port := range s.udpPorts {
		addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(port))
		if err != nil {
			return fmt.Errorf("无法解析UDP地址(端口%d): %v", port, err)
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("无法监听UDP端口%d: %v", port, err)
		}

		s.udpConns[port] = conn
		go s.handleUDPRequestsForPort(port)
	}
	return nil
}

// 为特定端口处理UDP请求
func (s *SMBServer) handleUDPRequestsForPort(port int) {
	conn := s.udpConns[port]
	buffer := make([]byte, 1024)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("UDP端口%d读取错误: %v\n", port, err)
			continue
		}

		// 根据不同端口处理不同协议
		switch port {
		case 137:
			if isNetBIOSDiscoveryRequest(buffer[:n]) {
				response := createNetBIOSDiscoveryResponse(s.NetBIOSName)
				conn.WriteToUDP(response, remoteAddr)
			}
		case 138:
			// 处理NetBIOS数据报服务请求
			if isNetBIOSDatagramRequest(buffer[:n]) {
				response := createNetBIOSDatagramResponse()
				conn.WriteToUDP(response, remoteAddr)
			}
		case 139:
			// 处理NetBIOS会话服务UDP请求
			if isNetBIOSSessionRequest(buffer[:n]) {
				response := createNetBIOSSessionResponse()
				conn.WriteToUDP(response, remoteAddr)
			}
		}
	}
}

// 检查是否是NetBIOS数据报请求
func isNetBIOSDatagramRequest(data []byte) bool {
	// 实现NetBIOS数据报请求检查逻辑
	return len(data) >= 14 && data[0] == 0x00 && data[1] == 0x00
}

// 创建NetBIOS数据报响应
func createNetBIOSDatagramResponse() []byte {
	// 构建NetBIOS数据报响应
	response := make([]byte, 14)
	response[0] = 0x81 // 响应标志
	response[1] = 0x00 // 状态码
	// 添加其他必要字段
	return response
}

// 检查是否是NetBIOS会话请求
func isNetBIOSSessionRequest(data []byte) bool {
	// 实现NetBIOS会话请求检查逻辑
	return len(data) >= 4 && bytes.Equal(data[:4], []byte{0x00, 0x00, 0x00, 0x00})
}

// 创建NetBIOS会话响应
func createNetBIOSSessionResponse() []byte {
	// 构建NetBIOS会话响应
	response := make([]byte, 4)
	binary.BigEndian.PutUint32(response, 0x00000000) // 成功状态
	return response
}

// CloseUDPServers 关闭所有UDP服务器连接
func (s *SMBServer) CloseUDPServers() {
	for port, conn := range s.udpConns {
		conn.Close()
		delete(s.udpConns, port)
	}
}

func makeSMBHeader(command uint8, status uint32) []byte {
	header := make([]byte, 32)
	header[0] = 0xFF
	header[1] = 'S'
	header[2] = 'M'
	header[3] = 'B'
	header[4] = command
	binary.LittleEndian.PutUint32(header[5:9], status)
	header[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(header[10:12], SMB_FLAGS2_UNICODE)
	return header
}

// createSessionSetupResponse 构建会话建立成功响应
func createSessionSetupResponse(uid uint16) []byte {
	// NetBIOS头 (4字节长度)
	netbiosHeader := make([]byte, 4)

	// SMB头 (32字节)
	smbHeader := makeSMBHeader(SMB_COM_SESSION_SETUP, 0)
	binary.LittleEndian.PutUint16(smbHeader[26:28], uid) // 会话UID

	// 构建响应体
	response := append(smbHeader, []byte{0x01}...)                                  // WordCount=1
	response = append(response, []byte{0x00, 0x00}...)                              // 状态码: 成功
	response = append(response, binary.LittleEndian.AppendUint16([]byte{}, uid)...) // UID
	response = append(response, []byte{0x00, 0x00, 0x00, 0x00}...)                  // 会话密钥
	response = append(response, []byte{0x00, 0x00}...)                              // 模拟级别
	response = append(response, []byte{0x00, 0x00}...)                              // 最大缓冲区大小
	response = append(response, []byte{0x00, 0x00}...)                              // ByteCount=0

	// 设置NetBIOS长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	// 组合完整响应
	return append(netbiosHeader, response...)
}
