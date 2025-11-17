package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"flup/output"
	"net"
	"path"
	"time"
)

// SMB FIND_FIRST2命令处理
func (s *SMBServer) handleFindFirst2(conn net.Conn, data []byte) error {
	if len(data) < 40 {
		return errors.New("invalid FIND_FIRST2 request")
	}

	// 解析参数
	fid := binary.LittleEndian.Uint16(data[29:31])
	filename, err := s.db.GetFilenameByFID(fid)
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_FIND_FIRST2, 0x00030002)
	}
	// 使用存储中间件获取文件列表
	ctx := context.Background()
	entries, err := s.storage.ListFiles(ctx, path.Join(s.PathPrefix, filename), "")
	if err != nil {
		return s.sendErrorResponse(conn, SMB_COM_FIND_FIRST2, 0x00030002)
	}

	// 生成SearchID
	s.mutex.Lock()
	searchID := s.nextSearchID
	s.nextSearchID++
	s.mutex.Unlock()

	// 初始化搜索状态
	maxResultsPerResponse := 20
	initialEntries := entries
	remainingEntries := entries
	if len(entries) > maxResultsPerResponse {
		initialEntries = entries[:maxResultsPerResponse]
		remainingEntries = entries[maxResultsPerResponse:]
	} else {
		remainingEntries = []output.FileInfo{}
	}

	// 存储搜索状态
	s.searchMutex.Lock()
	s.searchContinuations[searchID] = SearchState{
		Entries: entries,
		Index:   len(initialEntries),
	}
	s.searchMutex.Unlock()

	// 构建响应
	isEnd := len(remainingEntries) == 0
	return s.sendFindFirst2Response(conn, initialEntries, searchID, isEnd)
}

// 发送FIND_FIRST2响应
func (s *SMBServer) sendFindFirst2Response(conn net.Conn, entries []output.FileInfo, searchID uint16, isEnd bool) error {
	response := make([]byte, 0)

	// NetBIOS头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_FIND_FIRST2
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x0A) // 10个字参数

	// 参数块
	params := make([]byte, 20)
	params[0] = 0xFF                              // AndXCommand = 无后续命令
	params[1] = 0                                 // AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0) // AndXOffset
	binary.LittleEndian.PutUint16(params[4:6], searchID) // SearchID
	binary.LittleEndian.PutUint16(params[6:8], uint16(len(entries)))   // SearchCount
	endOfSearch := uint16(0)
	if isEnd {
		endOfSearch = 0xFFFF
	}
	binary.LittleEndian.PutUint16(params[8:10], endOfSearch) // EndOfSearch
	binary.LittleEndian.PutUint16(params[10:12], 0)                    // EaErrorOffset
	binary.LittleEndian.PutUint32(params[12:16], 0)                    // LastModified
	binary.LittleEndian.PutUint16(params[16:18], 0)                    // FileDataSize
	binary.LittleEndian.PutUint16(params[18:20], uint16(len(entries))) // SearchCount

	response = append(response, params...)

	// 构建文件信息
	var fileData []byte
	for _, entry := range entries {
		fileData = append(fileData, buildStandardInfo(entry)...) 
	}

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], uint16(len(fileData)))
	response = response[:len(response)+2]

	// 添加文件数据
	response = append(response, fileData...)

	// 设置NetBIOS长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}

// 构建标准文件信息结构
func buildStandardInfo(entry output.FileInfo) []byte {
	// 文件信息结构总长度: 32字节固定信息 + 文件名(可变长度)
	nameBytes := []byte(entry.Name)
	nameBytes = append(nameBytes, 0) // null终止
	fileInfo := make([]byte, 32+len(nameBytes))

	// 文件属性 (2字节)
	attrs := uint16(0x20) // 普通文件
	if entry.IsDir {
		attrs = 0x10 // 目录
	}
	binary.LittleEndian.PutUint16(fileInfo[0:2], attrs)

	// 最后写入时间 (8字节)
	binary.LittleEndian.PutUint64(fileInfo[2:10], getSMBTimeFromString(entry.UpdatedAt))

	// 文件大小 (4字节)
	binary.LittleEndian.PutUint32(fileInfo[10:14], uint32(entry.Size))

	// 文件名 (从32字节偏移开始)
	copy(fileInfo[32:], nameBytes)

	return fileInfo
}

// 从字符串转换时间为SMB格式
func getSMBTimeFromString(timeStr string) uint64 {
	// 解析Cloudreve返回的时间字符串
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return 0
	}
	return getSMBTime(t)
}

// 转换时间为SMB格式
func getSMBTime(t time.Time) uint64 {
	// SMB时间从1970-01-01 00:00:00 UTC开始的100纳秒间隔
	epoch := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	duration := t.Sub(epoch)
	return uint64(duration.Nanoseconds() / 100)
}

// 提取以null结尾的字符串
func extractNullTerminatedString(data []byte) string {
	nullIndex := 0
	for i, b := range data {
		if b == 0 {
			nullIndex = i
			break
		}
	}
	return string(data[:nullIndex])
}

// SMB FIND_NEXT2命令处理
func (s *SMBServer) handleFindNext2(conn net.Conn, data []byte) error {
	if len(data) < 40 {
		return errors.New("invalid FIND_NEXT2 request")
	}

	// 解析SearchID
	searchID := binary.LittleEndian.Uint16(data[29:31])

	// 获取搜索状态
	s.searchMutex.Lock()
	state, exists := s.searchContinuations[searchID]
	if !exists {
		s.searchMutex.Unlock()
		return s.sendErrorResponse(conn, SMB_COM_FIND_NEXT2, 0x00030002)
	}

	// 检查是否有更多结果
	if state.Index >= len(state.Entries) {
		s.searchMutex.Unlock()
		// 没有更多结果，发送结束响应
		return s.sendFindNext2Response(conn, []output.FileInfo{}, true)
	}

	// 获取下一批结果（最多20个）
	end := state.Index + 20
	if end > len(state.Entries) {
		end = len(state.Entries)
	}
	entries := state.Entries[state.Index:end]
	state.Index = end
	s.searchMutex.Unlock()

	// 发送响应
	return s.sendFindNext2Response(conn, entries, state.Index >= len(state.Entries))
}

// 发送FIND_NEXT2响应
func (s *SMBServer) sendFindNext2Response(conn net.Conn, entries []output.FileInfo, isEnd bool) error {
	response := make([]byte, 0)

	// NetBIOS头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = SMB_COM_FIND_NEXT2
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x0A) // 10个字参数

	// 参数块
	params := make([]byte, 20)
	params[0] = 0xFF					// AndXCommand
	params[1] = 0					// AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0)		// AndXOffset
	binary.LittleEndian.PutUint16(params[4:6], 0)		// SearchCount
	endOfSearch := uint16(0)
	if isEnd {
		endOfSearch = 0xFFFF
	}
	binary.LittleEndian.PutUint16(params[6:8], endOfSearch)	// EndOfSearch
	binary.LittleEndian.PutUint16(params[8:10], 0)		// EaErrorOffset
	binary.LittleEndian.PutUint32(params[10:14], 0)		// LastModified
	binary.LittleEndian.PutUint16(params[14:16], 0)		// FileDataSize
	binary.LittleEndian.PutUint16(params[16:18], 0)		// SearchCount
	binary.LittleEndian.PutUint16(params[18:20], endOfSearch)	// EndOfSearch

	response = append(response, params...)

	// 构建文件信息
	var fileData []byte
	for _, entry := range entries {
		fileData = append(fileData, buildStandardInfo(entry)...) 
	}

	// ByteCount
	binary.LittleEndian.PutUint16(response[len(response):], uint16(len(fileData)))
	response = response[:len(response)+2]

	// 添加文件数据
	response = append(response, fileData...)

	// 设置NetBIOS长度
	binary.BigEndian.PutUint32(netbiosHeader, uint32(len(response)))

	_, err := conn.Write(append(netbiosHeader, response...))
	return err
}