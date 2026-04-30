package auth

import "context"

type tracer interface {
	Start(context.Context, string) (context.Context, any)
}

func Validate(ctx context.Context) error {
	var t tracer
	_, _ = t.Start(ctx, "auth")
	return nil
}
