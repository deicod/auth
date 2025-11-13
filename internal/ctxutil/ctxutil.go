package ctxutil

import (
	"context"
	"errors"
	"log"

	"github.com/deicod/auth/core"
)

func NormalizeError(err error, op string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		if op != "" {
			log.Printf("auth deadline: %s: %v", op, err)
		} else {
			log.Printf("auth deadline: %v", err)
		}
		return core.ErrDeadline
	}
	return err
}
