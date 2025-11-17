package cloudreve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flup/output"
	"flup/storage"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
)

// CloudreveBackend Cloudreve存储后端实现
type CloudreveBackend struct {
	host string
	api  *API
}

// NewCloudreveBackend 创建Cloudreve后端实例
func NewCloudreveBackend(apiHost, policyID, user, pass string, db *storage.Database) *CloudreveBackend {
	return &CloudreveBackend{
		host: apiHost,
		api:  NewCloudreveAPI(apiHost, policyID, user, pass, db),
	}
}
func (c *CloudreveBackend) Name() string {
	return fmt.Sprintf("Cloudreve(%s)", c.host)
}

// UploadFile 实现文件上传接口
func (c *CloudreveBackend) UploadFile(ctx context.Context, path string, data io.Reader, size int64) error {
	session, err := c.api.InitUpload(ctx, path, size)
	if err != nil {
		return err
	}

	chunkSize := int64(session.ChunkSize)
	buffer := make([]byte, chunkSize)
	chunkIndex := 0

	for {
		n, err := data.Read(buffer)
		if err != nil && err != io.EOF {
			c.api.CancelUpload(ctx)
			return err
		}

		if n == 0 {
			break
		}

		if err := c.api.UploadChunk(ctx, session.UploadID, chunkIndex, buffer[:n]); err != nil {
			c.api.CancelUpload(ctx)
			return err
		}

		chunkIndex++

		if err == io.EOF {
			break
		}
	}

	return nil
}

// ListFiles 实现文件列表接口
func (c *CloudreveBackend) ListFiles(ctx context.Context, dir, name string) ([]output.FileInfo, error) {
	resp, err := c.api.GetFileList(ctx, dir, name)
	if err != nil {
		return nil, err
	}

	fileInfos := make([]output.FileInfo, len(resp.Files))
	for i, file := range resp.Files {
		fileInfos[i] = output.FileInfo{
			Name:      file.Name,
			Size:      file.Size,
			IsDir:     file.IsDir,
			CreatedAt: file.CreatedAt,
			UpdatedAt: file.UpdatedAt,
		}
	}

	return fileInfos, nil
}

// GetFileInfo 获取文件信息
func (c *CloudreveBackend) GetFileInfo(ctx context.Context, path string) (output.FileInfo, error) {
	return c.api.GetFileInfo(ctx, path)
}

// DeleteFile 删除文件
func (c *CloudreveBackend) DeleteFile(ctx context.Context, path string) error {
	return c.api.DeleteFile(ctx, path)
}

// GetFileDownloadURL 获取文件下载链接
func (c *CloudreveBackend) GetFileDownloadURL(ctx context.Context, path string) (string, error) {
	return c.api.GetFileDownloadURL(ctx, path)
}

// OpenFile 通过下载链接打开文件，支持偏移量和字节数限制读取
func (c *CloudreveBackend) OpenFile(ctx context.Context, path string, offset int64, maxBytes int64) (io.ReadCloser, error) {
	url, err := c.api.GetFileDownloadURL(ctx, path)
	if err != nil {
		return nil, err
	}

	// 创建HTTP请求
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 处理偏移量和字节数限制
	if offset > 0 || maxBytes > 0 {
		// 获取文件大小
		fileSize, err := c.getFileSize(ctx, url)
		if err != nil {
			return nil, err
		}

		// 计算起始位置（默认从开始处）
		start := offset
		if start < 0 {
			start = 0
		} else if start >= fileSize {
			return nil, errors.New("偏移超出文件大小")
		}

		// 计算结束位置
		var end int64
		if maxBytes > 0 {
			end = start + maxBytes - 1
			if end >= fileSize {
				end = fileSize - 1
			}
		}

		// 添加Range请求头
		rangeHeader := fmt.Sprintf("bytes=%d-", start)
		if maxBytes > 0 {
			rangeHeader = fmt.Sprintf("bytes=%d-%d", start, end)
		}
		req.Header.Set("Range", rangeHeader)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, fmt.Errorf("文件打开失败: %s", resp.Status)
	}

	return resp.Body, nil
}

// 获取文件大小
func (c *CloudreveBackend) getFileSize(ctx context.Context, url string) (int64, error) {
	headReq, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.ContentLength, nil
}
func (c *CloudreveBackend) CreateFile(ctx context.Context, path string) error {
	return c.api.CreateFile(ctx, path)
}
func (c *CloudreveBackend) CreateDir(ctx context.Context, path string) error {
	return c.api.CreateDir(ctx, path)
}

func (c *CloudreveBackend) Rename(ctx context.Context, oldPath, newPath string) error {
	// 获取文件信息以确定类型
	fileInfo, err := c.GetFileInfo(ctx, oldPath)
	if err != nil {
		return err
	}

	// 提取新文件名
	newName := filepath.Base(newPath)

	// 准备请求体
	reqBody := map[string]interface{}{
		"uri":      oldPath,
		"new_name": newName,
		"type":     0,
	}
	if fileInfo.IsDir {
		reqBody["type"] = 1
	}

	// 转换为JSON
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	// 创建请求
	url := fmt.Sprintf("%s/file/rename", c.host)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// 添加认证信息（假设API客户端已处理JWT等认证）
	// 实际实现应使用与其他API调用相同的认证方式

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		msg, _ := result["msg"].(string)
		return fmt.Errorf("重命名失败: %s", msg)
	}

	if code, ok := result["code"].(float64); ok && code != 0 {
		msg, _ := result["msg"].(string)
		return fmt.Errorf("重命名失败: %s", msg)
	}

	return nil
}

func (c *CloudreveBackend) Delete(ctx context.Context, uris []string, skipSoftDelete bool) error {
	// 准备请求体
	reqBody := map[string]interface{}{
		"uris":             uris,
		"skip_soft_delete": skipSoftDelete,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %v", err)
	}

	// 创建请求
	url := fmt.Sprintf("%s/file", c.host)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 解析响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		msg, _ := result["msg"].(string)
		return fmt.Errorf("删除失败: %s (状态码: %d)", msg, resp.StatusCode)
	}

	return nil
}
