package orders

import "context"

type dbLike interface {
	ExecContext(context.Context, string, ...any) (any, error)
}

func Save(ctx context.Context) error {
	var db dbLike
	_, _ = db.ExecContext(ctx, "insert into orders(id) values(?)", "ord_123")
	return nil
}
