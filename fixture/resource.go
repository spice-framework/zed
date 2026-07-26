package main

import (
	"context"
	"net/http"

	"github.com/StevenBuglione/spice/lifecycle"
)

type resource struct{}

// @Bean
func newServeMux() *http.ServeMux {
	return http.NewServeMux()
}

// @Bean
func newResource() (*resource, lifecycle.Cleanup, error) {
	cleanup := func(context.Context) error {
		return nil
	}
	return &resource{}, cleanup, nil
}
