package cllog

import (
	"fmt"
	"hnproxy/internal/clconfig"
	"io"
	"log/syslog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

// SyslogLevelWriter adapte syslog.Writer pour gérer les niveaux zerolog
type SyslogLevelWriter struct {
	writer *syslog.Writer
}

// InitLogger configure le logger global Zerolog
// Setup initialise le logger avec la configuration
func InitLogger(cfg clconfig.LoggerConfig, production bool) {
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		dir := path.Dir(file)
		file = path.Join(path.Base(dir), path.Base(file))
		return path.Base(file) + ":" + strconv.Itoa(line)
	}

	// Définir le niveau de log
	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	// Configurer le format de temps
	zerolog.TimeFieldFormat = time.RFC3339

	var writers []io.Writer

	// Writer pour la console
	if !production {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05",
			NoColor:    false,
		}
		writers = append(writers, consoleWriter)
	}

	// Writer pour le fichier si activé
	if cfg.File.Enable {
		fileWriter, err := setupFileWriter(cfg.File)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup file writer")
		}
		writers = append(writers, fileWriter)
	}

	// Writer syslog si activé
	if cfg.Syslog.Enable {
		syslogWriter, err := setupSyslogWriter(cfg.Syslog)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup syslog writer")
		}
		writers = append(writers, syslogWriter)
	}

	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	// Créer un multi-writer
	multi := io.MultiWriter(writers...)

	// Configurer le logger global
	log.Logger = zerolog.New(multi).
		With().
		Timestamp().
		Caller().
		Logger()

	environnment := "developpement"
	if production {
		environnment = "production"
	}
	log.Info().
		Str("environment", environnment).
		Str("level", cfg.Level).
		Bool("log_to_file", cfg.File.Enable).
		Bool("log_to_syslog", cfg.Syslog.Enable).
		Msg("Logger initialisé")
}

// setupFileWriter configure le writer pour les fichiers
func setupFileWriter(cfg clconfig.LoggerFileConfig) (io.Writer, error) {
	// Créer le dossier si nécessaire
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	fileWriter := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	return fileWriter, nil
}

// setupSyslogWriter configure le writer pour syslog
func setupSyslogWriter(cfg clconfig.LoggerSyslogConfig) (io.Writer, error) {
	// Utiliser un tag par défaut si non spécifié
	tag := cfg.Tag
	if tag == "" {
		tag = "littleblog"
	}
	// Utiliser une priorité par défaut si non spécifiée
	priority := cfg.Priority
	if priority == 0 {
		priority = syslog.LOG_INFO | syslog.LOG_LOCAL0
	}

	var writer *syslog.Writer
	var err error

	// Connexion locale ou distante
	if cfg.Protocol == "" || cfg.Address == "" {
		// Connexion locale (Unix socket)
		writer, err = syslog.New(priority, tag)
	} else {
		// Connexion distante (TCP ou UDP)
		writer, err = syslog.Dial(cfg.Protocol, cfg.Address, priority, tag)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	// Wrapper pour adapter syslog.Writer à io.Writer avec le bon niveau
	return &SyslogLevelWriter{writer: writer}, nil
}

// Write implémente io.Writer et route vers la bonne fonction syslog selon le niveau
func (w *SyslogLevelWriter) Write(p []byte) (n int, err error) {
	msg := string(p)

	// Parser le niveau depuis le JSON zerolog
	level := extractLevelFromJSON(msg)

	// Router vers la bonne méthode syslog selon le niveau
	switch level {
	case "debug":
		return len(p), w.writer.Debug(msg)
	case "info":
		return len(p), w.writer.Info(msg)
	case "warn", "warning":
		return len(p), w.writer.Warning(msg)
	case "error":
		return len(p), w.writer.Err(msg)
	case "fatal", "panic":
		return len(p), w.writer.Crit(msg)
	default:
		// Par défaut, utiliser Info
		return len(p), w.writer.Info(msg)
	}
}

// extractLevelFromJSON extrait le niveau de log d'un message JSON zerolog
// Format attendu: {"level":"info",...}
func extractLevelFromJSON(msg string) string {
	// Recherche simple du champ "level" dans le JSON
	// Format: "level":"xxx"
	startIdx := strings.Index(msg, `"level":"`)
	if startIdx == -1 {
		return ""
	}

	// Décaler après "level":"
	startIdx += 9

	// Trouver la fin (guillemet suivant)
	endIdx := strings.Index(msg[startIdx:], `"`)
	if endIdx == -1 {
		return ""
	}

	return msg[startIdx : startIdx+endIdx]
}

func parseLevel(level string) zerolog.Level {
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}
