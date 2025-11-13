package output

type Output interface {
	CreateFile(filename string, fileSize int64) error
	Upload(filename string, seek int64) error
	MoveFile(src, dst string) error
	DeleteFIle(filename string) error
}
