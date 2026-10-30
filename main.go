package main

import (
	"context"
	"flag"
	"fmt"
	"hnproxy/internal/clconfig"
	"hnproxy/internal/cllog"
	"hnproxy/internal/clserver"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

const VERSION string = "1.3.1"

// parseCommandLineArgs parses and validates command line arguments
func parseCommandLineArgs() (configFile string, shouldCreateExample bool, versionDisplay bool, err error) {
	var config = flag.String("config", "", "Fichier de configuration YAML")
	var example = flag.Bool("example", false, "Créer un fichier de configuration exemple")
	var version = flag.Bool("version", false, "version du produit")
	flag.Parse()

	if *version {
		return "", false, true, nil
	}

	if *example {
		return *config, true, false, nil
	}

	if *config == "" {
		return "", false, false, fmt.Errorf("fichier de configuration requis")
	}

	return *config, false, false, nil
}

func main() {
	// Parse command line arguments
	configFile, shouldCreateExample, versionDisplay, err := parseCommandLineArgs()
	if err != nil {
		fmt.Println("Usage:")
		fmt.Println("  hnProxy -config hnproxy.yaml")
		fmt.Println("  hnProxy -example  (pour créer un fichier exemple)")
		fmt.Println("  hnProxy -version  (affiche la version)")
		os.Exit(1)
	}

	if versionDisplay {
		println(VERSION)
		return
	}

	// Handle example creation
	if shouldCreateExample {
		if err := clconfig.HandleExampleCreation(configFile); err != nil {
			fmt.Printf("❌ %v\n", err)
		}
		return
	}

	// Load and validate configuration
	config, err := clconfig.LoadAndValidateConfig(configFile)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	cllog.InitLogger(config.Logger, config.Production)

	// Create and configure server
	server := clserver.NewServer(config)
	server.DisplayConfiguration(configFile)

	// Arrêt gracieux sur SIGINT / SIGTERM
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-sigCtx.Done()
		log.Info().Msg("🛑 Signal d'arrêt reçu, fermeture gracieuse en cours...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Erreur lors de la fermeture du serveur")
		}
	}()

	defer server.Close()

	// Start server
	if err := clserver.RunServer(server); err != nil {
		log.Fatal().Msg(fmt.Sprintf("❌ Erreur serveur: %v", err))
	}
}
