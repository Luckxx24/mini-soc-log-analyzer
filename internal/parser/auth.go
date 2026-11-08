package parser

import (
	"errors"
	"net"
	"strings"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/models"
)

func ParseAuthLog(line string) (models.AuthEvent, error) {
	linee := strings.TrimSpace(line)
	lines := strings.Fields(linee)

	if len(lines) != 6 {
		return models.AuthEvent{}, errors.New("panjang tidak tepat ")

	}

	if lines[1] != "password" || lines[2] != "for" || lines[4] != "from" {
		return models.AuthEvent{}, errors.New("format salah")

	}

	if lines[0] != "Failed" && lines[0] != "Accepted" {
		return models.AuthEvent{}, errors.New("format aktivitas login salah")
	}
	var Event string
	if lines[0] == "Failed" {
		Event = "failed_login"
	}

	if lines[0] == "Accepted" {
		Event = "successful_login"
	}

	Username := lines[3]

	ip := net.ParseIP(lines[5])

	if ip == nil {
		return models.AuthEvent{}, errors.New("error ketika menparse ip")
	}

	Auth := models.AuthEvent{
		Username:  Username,
		EventType: Event,
		SourceIP:  lines[5],
		RawLog:    line,
	}

	return Auth, nil

}
