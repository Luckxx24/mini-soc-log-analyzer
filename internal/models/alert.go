package models

type Alert struct {
	AlertType string
	SourceIP  string
	Attempts  int
	Message   string
}
