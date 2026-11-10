package main

import (
	"fmt"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/collector"
	"github.com/Luckxx24/mini-soc-log-analyzer/internal/detection"
	"github.com/Luckxx24/mini-soc-log-analyzer/internal/models"
	"github.com/Luckxx24/mini-soc-log-analyzer/internal/parser"
)

func main() {
	Texts, error := collector.ReadLines("testdata/auth.log")
	var Events []models.AuthEvent

	var successCount int
	var failedCount int
	if error != nil {
		fmt.Printf("erorr ketika membaca file %v", error)
		return
	}
	jumlah := len(Texts)
	for i, Text := range Texts {
		fmt.Printf("id: %d Text: %v\n", i+1, Text)
		auth, err := parser.ParseAuthLog(Text)

		if err != nil {
			fmt.Printf("eror di baris %d pesan error %v\n", i+1, err)
			failedCount++
			continue
		}
		Events = append(Events, auth)
		fmt.Printf("Event: %s\n", auth.EventType)
		fmt.Printf("Username: %s\n", auth.Username)
		fmt.Printf("IP: %s\n", auth.SourceIP)
		successCount++
	}

	alerts, err := detection.DetectBruteForce(Events, 5)

	for i, alert := range alerts {
		fmt.Printf("[%d] ALERT: %s\n", i+1, alert.AlertType)
		fmt.Printf("    Source IP: %s\n", alert.SourceIP)
		fmt.Printf("    Attempts: %d\n", alert.Attempts)
		fmt.Printf("    Message: %s\n\n", alert.Message)
	}

	if err != nil {
		fmt.Printf("ERROR %v", err)
		return
	}

	fmt.Printf("jumlah logs %d\n", jumlah)
	fmt.Printf("succed parsed %d\n", successCount)
	fmt.Printf("failed logs %d\n", failedCount)

}
