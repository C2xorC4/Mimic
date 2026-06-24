package control

import (
	"bufio"
	"fmt"
	"os"
)

// TailFile returns up to n trailing lines from path.
func TailFile(path string, n int) (LogTail, error) {
	if n <= 0 {
		n = 50
	}
	if n > 5000 {
		n = 5000
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return LogTail{Path: path, Lines: []string{}, Total: 0}, nil
		}
		return LogTail{}, fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return LogTail{}, fmt.Errorf("read log: %w", err)
	}
	return LogTail{
		Path:  path,
		Lines: lines,
		Total: len(lines),
	}, nil
}