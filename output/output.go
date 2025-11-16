package output

import (
	"context"
	"io"
)

// BackendStorage 存储后端接口定义
type BackendStorage interface {
	Name() string
	UploadFile(ctx context.Context, path string, data io.Reader, size int64) error
	ListFiles(ctx context.Context, dir, name string) ([]FileInfo, error)
	GetFileInfo(ctx context.Context, path string) (FileInfo, error)
	DeleteFile(ctx context.Context, path string) error
	GetFileDownloadURL(ctx context.Context, path string) (string, error)
	OpenFile(ctx context.Context, path string) (io.ReadCloser, error)
	CreateFile(ctx context.Context, path string) error
	CreateDir(ctx context.Context, path string) error
}

// FileInfo 文件信息结构体
type FileInfo struct {
	Name      string
	Size      int64
	IsDir     bool
	CreatedAt string
	UpdatedAt string
}
