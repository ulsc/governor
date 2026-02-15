package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestChannelSinkEmitAddsTimestampAndForwardsEvent(t *testing.T) {
	ch := make(chan Event, 1)
	sink := NewChannelSink(ch)

	sink.Emit(Event{
		Type:  EventRunStarted,
		RunID: "run-1",
	})

	select {
	case got := <-ch:
		if got.Type != EventRunStarted {
			t.Fatalf("expected type %q, got %q", EventRunStarted, got.Type)
		}
		if got.RunID != "run-1" {
			t.Fatalf("expected run id run-1, got %q", got.RunID)
		}
		if got.At.IsZero() {
			t.Fatal("expected timestamp to be auto-populated")
		}
		if got.At.Location() != time.UTC {
			t.Fatalf("expected UTC timestamp location, got %q", got.At.Location())
		}
	default:
		t.Fatal("expected event to be sent to channel")
	}
}

func TestChannelSinkEmitDropsOnBackpressureWithoutBlocking(t *testing.T) {
	const ciTimeout = 5 * time.Second

	ch := make(chan Event, 1)
	ch <- Event{Type: EventWorkerStarted, Track: "worker-1"}
	sink := NewChannelSink(ch)

	done := make(chan struct{})
	go func() {
		sink.Emit(Event{Type: EventWorkerStarted, Track: "worker-2"})
		close(done)
	}()

	select {
	case <-done:
		// Expected: emit should return immediately and drop when channel is full.
	case <-time.After(ciTimeout):
		t.Fatal("expected Emit to return without blocking on full channel")
	}

	select {
	case got := <-ch:
		if got.Track != "worker-1" {
			t.Fatalf("expected original buffered event to remain, got %q", got.Track)
		}
	case <-time.After(ciTimeout):
		t.Fatal("expected original buffered event to remain available")
	}

	select {
	case extra := <-ch:
		t.Fatalf("expected dropped event, but received %+v", extra)
	default:
	}
}

func TestPlainSinkEmitFormatsAndSkipsUnknownEvents(t *testing.T) {
	var out bytes.Buffer
	sink := NewPlainSink(&out)

	sink.Emit(Event{
		Type:  EventRunWarning,
		Error: " warning from fallback ",
	})
	sink.Emit(Event{
		Type:         EventWorkerFinished,
		At:           time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC),
		Track:        "hardcoded_credentials",
		Status:       "done",
		FindingCount: 2,
		DurationMS:   17,
		Error:        " permission denied ",
	})
	sink.Emit(Event{Type: EventType("unknown")})

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two formatted lines, got %d: %q", len(lines), out.String())
	}

	if !strings.Contains(lines[0], "warning: warning from fallback") {
		t.Fatalf("expected warning fallback message in first line, got %q", lines[0])
	}

	const wantSecond = "[03:04:05] worker hardcoded_credentials finished status=done findings=2 duration=17ms error=permission denied"
	if lines[1] != wantSecond {
		t.Fatalf("unexpected worker-finished format:\nwant: %q\n got: %q", wantSecond, lines[1])
	}
}
