package detection

import (
	"errors"
	"time"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/models"
)

func DetectBruteForce(Events []models.AuthEvent, threshold int, window time.Duration) ([]models.Alert, error) {
	if threshold <= 0 {
		return []models.Alert{}, errors.New("threshold tifak boleh kurang atau sama dengan 0")
	}
	var alerts []models.Alert
	ipAttempt := make(map[string][]time.Time)

	for _, Event := range Events {

		if Event.EventType == "failed_login" {
			cutoff := Event.Timestamp.Add(-window)
			oldAttempt := ipAttempt[Event.SourceIP]
			var activeAttempts []time.Time
			for _, value := range oldAttempt {
				if value.After(cutoff) || value.Equal(cutoff) {
					activeAttempts = append(activeAttempts, value)

				}

			}
			activeAttempts = append(activeAttempts, Event.Timestamp)
			ipAttempt[Event.SourceIP] = activeAttempts

			if len(activeAttempts) == threshold {
				Alert := models.Alert{
					AlertType: "sliding window",
					SourceIP:  Event.SourceIP,
					Attempts:  len(activeAttempts),
					Message:   "IP melewati batas wajar",
				}

				alerts = append(alerts, Alert)
			}

		}

	}
	return alerts, nil
}
