package ctxutil

import (
	"context"
	"errors"
	"testing"

	"github.com/deicod/auth/core"
)

func TestNormalizeErrorDeadline(t *testing.T) {
	err := NormalizeError(context.DeadlineExceeded, "op")
	if !errors.Is(err, core.ErrDeadline) {
		t.Fatalf("expected ErrDeadline, got %v", err)
	}
}

func TestNormalizeErrorPassthrough(t *testing.T) {
	sentinel := errors.New("boom")
	if got := NormalizeError(sentinel, "op"); !errors.Is(got, sentinel) {
		t.Fatalf("expected passthrough error")
	}
}

func TestNormalizeErrorNil(t *testing.T) {
	if got := NormalizeError(nil, "op"); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}
