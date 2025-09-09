package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

// parseCommandLineArgs parses and validates command line arguments
func parseCommandLineArgs() (configFile string, shouldCreateExample bool, err error) {
	var config = flag.String("config", "", "Fichier de configuration YAML")
	var example = flag.Bool("example", false, "Créer un fichier de configuration exemple")
	var version = flag.Bool("version", false, "version du produit")
	flag.Parse()

	if *version {
		println(VERSION)
		os.Exit(0)
	}

	if *example {
		return "", true, nil
	}

	if *config == "" {
		return "", false, fmt.Errorf("fichier de configuration requis")
	}

	return *config, false, nil
}

func main() {
	// Parse command line arguments
	configFile, shouldCreateExample, err := parseCommandLineArgs()
	if err != nil {
		fmt.Println("hnProxy " + VERSION)
		fmt.Println("Usage:")
		fmt.Println("  hnProxy -config config.yaml")
		fmt.Println("  hnProxy -example  (pour créer un fichier exemple)")
		os.Exit(1)
	}

	// Handle example creation
	if shouldCreateExample {
		if err := handleExampleCreation(); err != nil {
			log.Fatalf("❌ %v", err)
		}
		return
	}

	// Load and validate configuration
	config, err := loadAndValidateConfig(configFile)
	if err != nil {
		log.Fatalf("❌ %v", err)
	}

	// Create and configure server
	server := NewServer(config)
	server.DisplayConfiguration(configFile)

	// Start server
	if err := runServer(server); err != nil {
		log.Fatalf("❌ Erreur serveur: %v", err)
	}
}
