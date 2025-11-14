package cloudreve

import (
	"context"
	"flup/output"
	"flup/storage"
	"fmt"
	"io"
	"net/http"
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

// OpenFile 通过下载链接打开文件
func (c *CloudreveBackend) OpenFile(ctx context.Context, path string) (io.ReadCloser, error) {
	url, err := c.api.GetFileDownloadURL(ctx, path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to download file: %s", resp.Status)
	}

	return resp.Body, nil
}

func (c *CloudreveBackend) CreateFile(ctx context.Context, path string) error {
	return c.api.CreateFile(ctx, path)
}
func (c *CloudreveBackend) CreateDir(ctx context.Context, path string) error {
	return c.api.CreateDir(ctx, path)
}
