package parser

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/models"
)

func ParseAuthLog(line string) (models.AuthEvent, error) {
	linee := strings.TrimSpace(line)
	lines := strings.Fields(linee)

	if len(lines) != 7 {
		return models.AuthEvent{}, errors.New("panjang tidak tepat ")

	}

	if lines[2] != "password" || lines[3] != "for" || lines[5] != "from" {
		return models.AuthEvent{}, errors.New("format salah")

	}

	if lines[1] != "Failed" && lines[1] != "Accepted" {
		return models.AuthEvent{}, errors.New("format aktivitas login salah")
	}
	var Event string
	if lines[1] == "Failed" {
		Event = "failed_login"
	}

	if lines[1] == "Accepted" {
		Event = "successful_login"
	}

	Username := lines[4]

	ip := net.ParseIP(lines[6])

	if ip == nil {
		return models.AuthEvent{}, errors.New("error ketika menparse ip")
	}
	tl, err := time.Parse(time.RFC3339, lines[0])

	if err != nil {
		return models.AuthEvent{}, errors.New("error kandungan pertama harsu waktu ")
	}

	Auth := models.AuthEvent{
		Username:  Username,
		EventType: Event,
		SourceIP:  lines[5],
		RawLog:    line,
		Timestamp: tl,
	}

	return Auth, nil

}
