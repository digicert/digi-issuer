package caclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestDoAddsUniqueTransactionID(t *testing.T) {
	transactionIDs := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		transactionIDs <- request.Header.Get(transactionIDHeader)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := New(server.URL, &APIKeyAuth{APIKey: "test-api-key"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for range 2 {
		if err := client.do(context.Background(), http.MethodGet, "/health", nil, nil); err != nil {
			t.Fatalf("do() error = %v", err)
		}
	}

	first := <-transactionIDs
	second := <-transactionIDs
	if _, err := uuid.Parse(first); err != nil {
		t.Errorf("first transaction ID %q is not a UUID: %v", first, err)
	}
	if _, err := uuid.Parse(second); err != nil {
		t.Errorf("second transaction ID %q is not a UUID: %v", second, err)
	}
	if first == second {
		t.Error("transaction IDs must be unique per request")
	}
}
