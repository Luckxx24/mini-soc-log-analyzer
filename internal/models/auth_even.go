package models

import "time"

type AuthEvent struct {
	Username  string
	SourceIP  string
	EventType string
	RawLog    string
	Timestamp time.Time
}
