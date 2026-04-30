package payment

import (
	"context"
	"errors"
	"net/http"
)

func Charge(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.internal/charge", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return errors.New("payment failed")
	}
	return nil
}
