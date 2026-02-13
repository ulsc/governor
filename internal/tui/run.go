package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"governor/internal/progress"
)

type Options struct {
	Events <-chan progress.Event
}

func Run(opts Options) error {
	if opts.Events == nil {
		return fmt.Errorf("tui events channel is required")
	}

	m := newModel(opts.Events)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
