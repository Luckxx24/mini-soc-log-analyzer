package models

type AuthEvent struct {
	Username  string
	SourceIP  string
	EventType string
	RawLog    string
}
