package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type Sink interface {
	Emit(Event)
}

type SinkFunc func(Event)

func (f SinkFunc) Emit(e Event) {
	f(e)
}

type NoopSink struct{}

func (NoopSink) Emit(Event) {}

type ChannelSink struct {
	ch chan<- Event
}

func NewChannelSink(ch chan<- Event) *ChannelSink {
	return &ChannelSink{ch: ch}
}

func (s *ChannelSink) Emit(e Event) {
	if s == nil || s.ch == nil {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	select {
	case s.ch <- e:
	default:
		// Drop on backpressure so an absent/slow UI cannot block worker execution.
	}
}

type PlainSink struct {
	w  io.Writer
	mu sync.Mutex
}

func NewPlainSink(w io.Writer) *PlainSink {
	return &PlainSink{w: w}
}

func (s *PlainSink) Emit(e Event) {
	if s == nil || s.w == nil {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}

	line := formatPlain(e)
	if line == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = fmt.Fprintln(s.w, line)
}

func formatPlain(e Event) string {
	ts := e.At.Format("15:04:05")
	switch e.Type {
	case EventRunStarted:
		return fmt.Sprintf("[%s] run %s started", ts, e.RunID)
	case EventRunWarning:
		msg := strings.TrimSpace(e.Message)
		if msg == "" {
			msg = strings.TrimSpace(e.Error)
		}
		return fmt.Sprintf("[%s] warning: %s", ts, msg)
	case EventRunFinished:
		line := fmt.Sprintf("[%s] run %s finished status=%s findings=%d duration=%dms", ts, e.RunID, e.Status, e.FindingCount, e.DurationMS)
		if strings.TrimSpace(e.Error) != "" {
			line += " error=" + strings.TrimSpace(e.Error)
		}
		return line
	case EventWorkerStarted:
		return fmt.Sprintf("[%s] worker %s started", ts, e.Track)
	case EventWorkerHeartbeat:
		return fmt.Sprintf("[%s] worker %s running duration=%dms", ts, e.Track, e.DurationMS)
	case EventWorkerOutput:
		return fmt.Sprintf("[%s] worker %s output ready", ts, e.Track)
	case EventWorkerFinished:
		line := fmt.Sprintf("[%s] worker %s finished status=%s findings=%d duration=%dms", ts, e.Track, e.Status, e.FindingCount, e.DurationMS)
		if strings.TrimSpace(e.Error) != "" {
			line += " error=" + strings.TrimSpace(e.Error)
		}
		return line
	default:
		return ""
	}
}
