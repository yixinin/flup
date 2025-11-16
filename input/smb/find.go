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
		return s.sendErrorResponse(conn, 0x0F, 0x00030002)
	}
	// 使用存储中间件获取文件列表
	ctx := context.Background()
	entries, err := s.storage.ListFiles(ctx, path.Join(s.PathPrefix, filename), "")
	if err != nil {
		return s.sendErrorResponse(conn, 0x0F, 0x00030002)
	}

	// 构建响应
	return s.sendFindFirst2Response(conn, entries)
}

// 发送FIND_FIRST2响应
func (s *SMBServer) sendFindFirst2Response(conn net.Conn, entries []output.FileInfo) error {
	response := make([]byte, 0)

	// NetBIOS头
	netbiosHeader := make([]byte, 4)

	// SMB头
	smbHeader := make([]byte, 32)
	smbHeader[0] = 0xFF
	smbHeader[1] = 'S'
	smbHeader[2] = 'M'
	smbHeader[3] = 'B'
	smbHeader[4] = 0x0F // FIND_FIRST2命令
	smbHeader[9] = SMB_FLAGS_CANONICALIZED_PATHS
	binary.LittleEndian.PutUint16(smbHeader[10:12], SMB_FLAGS2_UNICODE)

	response = append(response, smbHeader...)

	// WordCount
	response = append(response, 0x0A) // 10个字参数

	// 参数块
	params := make([]byte, 20)
	params[0] = 0xFF                                                   // AndXCommand
	params[1] = 0                                                      // AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0)                      // AndXOffset
	binary.LittleEndian.PutUint16(params[4:6], 0)                      // SearchCount
	binary.LittleEndian.PutUint16(params[6:8], uint16(len(entries)))   // EndOfSearch
	binary.LittleEndian.PutUint16(params[8:10], 0)                     // EaErrorOffset
	binary.LittleEndian.PutUint32(params[10:14], 0)                    // LastModified
	binary.LittleEndian.PutUint16(params[14:16], 0)                    // FileDataSize
	binary.LittleEndian.PutUint16(params[16:18], 0)                    // SearchCount
	binary.LittleEndian.PutUint16(params[18:20], uint16(len(entries))) // EndOfSearch

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
	fileInfo := make([]byte, 48)

	// 文件名称
	nameBytes := []byte(entry.Name)
	nameBytes = append(nameBytes, 0) // null终止
	fileInfo = append(fileInfo, nameBytes...)

	// 文件属性
	attrs := uint16(0x20) // 普通文件
	if entry.IsDir {
		attrs = 0x10 // 目录
	}
	binary.LittleEndian.PutUint16(fileInfo[0:2], attrs)

	// 最后写入时间
	binary.LittleEndian.PutUint64(fileInfo[2:10], getSMBTimeFromString(entry.UpdatedAt))

	// 文件大小
	binary.LittleEndian.PutUint32(fileInfo[10:14], uint32(entry.Size))

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
