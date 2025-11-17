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
	OpenFile(ctx context.Context, path string, offset int64, maxBytes int64) (io.ReadCloser, error)
	CreateFile(ctx context.Context, path string) error
	CreateDir(ctx context.Context, path string) error
	Rename(ctx context.Context, oldPath, newPath string) error
	Delete(ctx context.Context, uris []string, skipSoftDelete bool) error
}

// FileInfo 文件信息结构体
type FileInfo struct {
	Name      string
	Size      int64
	IsDir     bool
	CreatedAt string
	UpdatedAt string
}
