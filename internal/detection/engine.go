package detection

import (
	"errors"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/models"
)

func DetectBruteForce(Events []models.AuthEvent, threshold int) ([]models.Alert, error) {
	if threshold <= 0 {
		return []models.Alert{}, errors.New("threshold tifak boleh kurang atau sama dengan 0")
	}

	ipAttempt := make(map[string]int)

	for _, Info := range Events {

		if Info.EventType == "failed_login" {

			ipAttempt[Info.SourceIP]++

		}

	}
	var alerts []models.Alert
	for i, Attempt := range ipAttempt {
		if Attempt >= threshold {
			Alert := models.Alert{
				AlertType: "ssh_brute_force",
				SourceIP:  i,
				Attempts:  Attempt,
				Message:   "IP melewati batas wajar",
			}

			alerts = append(alerts, Alert)
		}

	}

	return alerts, nil
}
