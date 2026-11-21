package parser

import (
	"testing"
	"time"
)

func TestAuth(T *testing.T) {
	auth, err := ParseAuthLog("2026-11-17T10:00:00Z Failed password for admin from alamat-ip-salah")
	if err != nil {
		T.Errorf("gagal memparse data dummy")
		return
	}

	if auth.EventType != "failed_login" {
		T.Errorf("keluaran tidak sesuai")
		return

	}
	timedparse, erro := time.Parse(time.RFC3339, "2026-11-17T10:00:00Z")
	if erro != nil {
		T.Errorf("gagal memprase waktu")
		return
	}

	if ok := auth.Timestamp.Equal(timedparse); !ok {
		T.Errorf("waktu tidak cocok")
		return
	}

	if auth.SourceIP != "192.168.1.10" {
		T.Errorf("ip tidak sama atau ip gagal")
		return

	}

	if auth.Username != "admin" {
		T.Errorf("nama username tidak sama")
	}
}
