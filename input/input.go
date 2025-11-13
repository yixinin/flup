package input

type Input interface {
	Upload(filename string) error
}
