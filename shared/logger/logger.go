package logger

import (
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

var (
	L    *log.Logger
	once sync.Once
)

func newLogger(output *os.File, minLevel log.Level) *log.Logger {
	styles := log.DefaultStyles()

	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().
		SetString("DEBUG").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("63")).
		Foreground(lipgloss.Color("0")).
		Bold(true)

	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().
		SetString("INFO").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("86")).
		Foreground(lipgloss.Color("0")).
		Bold(true)

	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().
		SetString("WARN").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("192")).
		Foreground(lipgloss.Color("0")).
		Bold(true)

	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("ERROR").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("203")).
		Foreground(lipgloss.Color("0")).
		Bold(true)

	styles.Levels[log.FatalLevel] = lipgloss.NewStyle().
		SetString("FATAL").
		Padding(0, 1, 0, 1).
		Background(lipgloss.Color("204")).
		Foreground(lipgloss.Color("0")).
		Bold(true)

	logger := log.New(output)
	logger.SetStyles(styles)
	logger.SetLevel(minLevel)
	logger.SetReportCaller(true)
	logger.SetTimeFormat(time.RFC3339)

	return logger
}

func InitLogger(output *os.File, minLevel log.Level) {
	once.Do(func() {
		L = newLogger(output, minLevel)
	})
}
