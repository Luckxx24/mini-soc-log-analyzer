package collector

import (
	"bufio"
	"os"
)

func ReadLines(path string) ([]string, error) {

	file, error := os.Open(path)
	if error != nil {
		return nil, error
	}
	defer file.Close()

	var Text []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		Text = append(Text, scanner.Text())

	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return Text, nil

}
