package checkstui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

type Options struct {
	ChecksDir string
}

func Run(opts Options) error {
	m, err := newModel(opts)
	if err != nil {
		return err
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	if err != nil {
		return fmt.Errorf("run checks tui: %w", err)
	}
	return nil
}

