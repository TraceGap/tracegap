package main

import (
	"context"

	"example.com/checkout-go/internal/checkout"
)

func main() {
	_ = checkout.SubmitOrderHandler(context.Background())
}
