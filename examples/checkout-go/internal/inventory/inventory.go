package inventory

import "context"

type tracer interface {
	Start(context.Context, string) (context.Context, any)
}

func Reserve(ctx context.Context) error {
	var t tracer
	_, _ = t.Start(ctx, "inventory")
	return nil
}
