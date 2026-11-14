package detection

import (
	"testing"
	"time"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/models"
)

// Membuat event dummy dengan waktu yang sudah ditentukan.
func makeAuthEvent(ip, eventType string, seconds int) models.AuthEvent {
	baseTime := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

	return models.AuthEvent{
		Username:  "admin",
		EventType: eventType,
		SourceIP:  ip,
		Timestamp: baseTime.Add(time.Duration(seconds) * time.Second),
	}
}

func TestDetectBruteForce(t *testing.T) {
	tests := []struct {
		name       string
		events     []models.AuthEvent
		wantAlerts int
	}{
		{
			name: "Brute force terdeteksi",
			events: []models.AuthEvent{
				makeAuthEvent("192.168.1.10", "failed_login", 0),
				makeAuthEvent("192.168.1.10", "failed_login", 10),
				makeAuthEvent("192.168.1.10", "failed_login", 20),
				makeAuthEvent("192.168.1.10", "failed_login", 30),
				makeAuthEvent("192.168.1.10", "failed_login", 40),
			},
			wantAlerts: 1,
		},
		{
			name: "Percobaan di bawah threshold",
			events: []models.AuthEvent{
				makeAuthEvent("192.168.1.20", "failed_login", 0),
				makeAuthEvent("192.168.1.20", "failed_login", 10),
				makeAuthEvent("192.168.1.20", "failed_login", 20),
				makeAuthEvent("192.168.1.20", "failed_login", 30),
			},
			wantAlerts: 0,
		},
		{
			name: "Timestamp lama kedaluwarsa",
			events: []models.AuthEvent{
				makeAuthEvent("192.168.1.30", "failed_login", 0),
				makeAuthEvent("192.168.1.30", "failed_login", 10),
				makeAuthEvent("192.168.1.30", "failed_login", 20),
				makeAuthEvent("192.168.1.30", "failed_login", 30),
				makeAuthEvent("192.168.1.30", "failed_login", 65),
			},
			wantAlerts: 0,
		},
		{
			name: "Percobaan dari IP berbeda tidak tercampur",
			events: []models.AuthEvent{
				makeAuthEvent("192.168.1.40", "failed_login", 0),
				makeAuthEvent("192.168.1.50", "failed_login", 5),
				makeAuthEvent("192.168.1.40", "failed_login", 10),
				makeAuthEvent("192.168.1.50", "failed_login", 15),
				makeAuthEvent("192.168.1.40", "failed_login", 20),
				makeAuthEvent("192.168.1.50", "failed_login", 25),
			},
			wantAlerts: 0,
		},
		{
			name: "Login berhasil tidak dihitung",
			events: []models.AuthEvent{
				makeAuthEvent("192.168.1.60", "failed_login", 0),
				makeAuthEvent("192.168.1.60", "successful_login", 5),
				makeAuthEvent("192.168.1.60", "failed_login", 10),
				makeAuthEvent("192.168.1.60", "successful_login", 15),
				makeAuthEvent("192.168.1.60", "failed_login", 20),
				makeAuthEvent("192.168.1.60", "failed_login", 30),
				makeAuthEvent("192.168.1.60", "failed_login", 40),
			},
			wantAlerts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alerts, err := DetectBruteForce(
				tt.events,
				5,
				60*time.Second,
			)

			if err != nil {
				t.Fatalf("DetectBruteForce() error = %v", err)
			}

			if len(alerts) != tt.wantAlerts {
				t.Errorf(
					"jumlah alert = %d, ingin %d",
					len(alerts),
					tt.wantAlerts,
				)
			}

			if tt.wantAlerts > 0 {
				if alerts[0].Attempts != 5 {
					t.Errorf(
						"Attempts = %d, ingin 5",
						alerts[0].Attempts,
					)
				}
			}
		})
	}
}
