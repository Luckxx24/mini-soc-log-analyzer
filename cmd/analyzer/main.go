package main

import (
	"fmt"

	"github.com/Luckxx24/mini-soc-log-analyzer/internal/collector"
	"github.com/Luckxx24/mini-soc-log-analyzer/internal/parser"
)

func main() {
	Texts, error := collector.ReadLines("testdata/auth.log")

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

		fmt.Printf("Event: %s\n", auth.EventType)
		fmt.Printf("Username: %s\n", auth.Username)
		fmt.Printf("IP: %s\n", auth.SourceIP)
		successCount++
	}

	fmt.Printf("jumlah logs %d\n", jumlah)
	fmt.Printf("succed parsed %d\n", successCount)
	fmt.Printf("failed logs %d\n", failedCount)
}
