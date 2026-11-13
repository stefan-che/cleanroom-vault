package main

import (
	"encoding/json"
	"log"
	"os"
)

var appConfig Config

type Config struct {
	// MasterKey is the current master key, wrapped with the KEK.
	MasterKey string `json:"master_key"`
	// PreviousKeys holds former master keys (also wrapped with the KEK) for backward
	// compatibility after rotation: older records are decrypted with them.
	PreviousKeys []string `json:"previous_keys"`

	Connect1 string `json:"connect1"`
	Connect2 string `json:"connect2"`
	Connect3 string `json:"connect3"`
	Connect4 string `json:"connect4"`
	Connect5 string `json:"connect5"`
}

func readConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal("Error code 1")
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	appConfig = *(new(Config))
	err = decoder.Decode(&appConfig)
	if err != nil {
		log.Fatal("Error code 2")
	}
}
