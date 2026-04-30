package checkout

import (
	"context"

	"example.com/checkout-go/internal/auth"
	"example.com/checkout-go/internal/inventory"
	"example.com/checkout-go/internal/orders"
	"example.com/checkout-go/internal/payment"
)

func SubmitOrderHandler(ctx context.Context) error {
	if err := auth.Validate(ctx); err != nil {
		return err
	}
	if err := inventory.Reserve(ctx); err != nil {
		return err
	}
	if err := payment.Charge(ctx); err != nil {
		return err
	}
	return orders.Save(ctx)
}
