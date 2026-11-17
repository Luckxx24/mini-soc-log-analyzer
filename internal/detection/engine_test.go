package detection

import (
	"testing"
	"time"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/models"
)

// Membuat event dummy.
func makeAuthEvent(ip, eventType string, seconds int) models.AuthEvent {
	baseTime := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

	return models.AuthEvent{
		Username:  "admin",
		EventType: eventType,
		SourceIP:  ip,
		Timestamp: baseTime.Add(time.Duration(seconds) * time.Second),
	}
}

// Helper untuk memeriksa hasil detection.
func checkDetection(t *testing.T, events []models.AuthEvent, wantAlerts int) {
	t.Helper()

	alerts, err := DetectBruteForce(events, 5, 60*time.Second)

	if err != nil {
		t.Fatalf("Terjadi error: %v", err)
	}

	if len(alerts) != wantAlerts {
		t.Errorf("Jumlah alert = %d, ingin %d", len(alerts), wantAlerts)
	}

	if wantAlerts > 0 && len(alerts) > 0 {
		if alerts[0].Attempts != 5 {
			t.Errorf("Attempts = %d, ingin 5", alerts[0].Attempts)
		}
	}
}

// Test 1: Brute force terdeteksi.
func TestBruteForceDetected(t *testing.T) {
	events := []models.AuthEvent{
		makeAuthEvent("192.168.1.10", "failed_login", 0),
		makeAuthEvent("192.168.1.10", "failed_login", 10),
		makeAuthEvent("192.168.1.10", "failed_login", 20),
		makeAuthEvent("192.168.1.10", "failed_login", 30),
		makeAuthEvent("192.168.1.10", "failed_login", 40),
	}

	checkDetection(t, events, 1)
}

// Test 2: Percobaan di bawah threshold.
func TestBelowThreshold(t *testing.T) {
	events := []models.AuthEvent{
		makeAuthEvent("192.168.1.20", "failed_login", 0),
		makeAuthEvent("192.168.1.20", "failed_login", 10),
		makeAuthEvent("192.168.1.20", "failed_login", 20),
		makeAuthEvent("192.168.1.20", "failed_login", 30),
	}

	checkDetection(t, events, 0)
}

// Test 3: Timestamp lama kedaluwarsa.
func TestExpiredTimestamp(t *testing.T) {
	events := []models.AuthEvent{
		makeAuthEvent("192.168.1.30", "failed_login", 0),
		makeAuthEvent("192.168.1.30", "failed_login", 10),
		makeAuthEvent("192.168.1.30", "failed_login", 20),
		makeAuthEvent("192.168.1.30", "failed_login", 30),
		makeAuthEvent("192.168.1.30", "failed_login", 65),
	}

	checkDetection(t, events, 0)
}

// Test 4: Percobaan dari IP berbeda.
func TestDifferentIPs(t *testing.T) {
	events := []models.AuthEvent{
		makeAuthEvent("192.168.1.40", "failed_login", 0),
		makeAuthEvent("192.168.1.50", "failed_login", 5),
		makeAuthEvent("192.168.1.40", "failed_login", 10),
		makeAuthEvent("192.168.1.50", "failed_login", 15),
		makeAuthEvent("192.168.1.40", "failed_login", 20),
		makeAuthEvent("192.168.1.50", "failed_login", 25),
	}

	checkDetection(t, events, 0)
}

// Test 5: Login berhasil tidak dihitung.
func TestSuccessfulLoginNotCounted(t *testing.T) {
	events := []models.AuthEvent{
		makeAuthEvent("192.168.1.60", "failed_login", 0),
		makeAuthEvent("192.168.1.60", "successful_login", 5),
		makeAuthEvent("192.168.1.60", "failed_login", 10),
		makeAuthEvent("192.168.1.60", "successful_login", 15),
		makeAuthEvent("192.168.1.60", "failed_login", 20),
		makeAuthEvent("192.168.1.60", "failed_login", 30),
		makeAuthEvent("192.168.1.60", "failed_login", 40),
	}

	checkDetection(t, events, 1)
}

func TestInvalidThreshold(t *testing.T) {
	_, err := DetectBruteForce(nil, 0, 60*time.Second)

	if err == nil {
		t.Error("seharusnya menghasilkan error")
	}
}

func TestInvalidWindow(t *testing.T) {
	_, err := DetectBruteForce(nil, 5, 0)

	if err == nil {
		t.Error("seharusnya menghasilkan error")
	}
}

func TestTimestampAtWindowBoundary(t *testing.T) {
	events := []models.AuthEvent{
		makeAuthEvent("192.168.1.70", "failed_login", 0),
		makeAuthEvent("192.168.1.70", "failed_login", 10),
		makeAuthEvent("192.168.1.70", "failed_login", 20),
		makeAuthEvent("192.168.1.70", "failed_login", 30),
		makeAuthEvent("192.168.1.70", "failed_login", 60),
	}

	checkDetection(t, events, 1)
}
