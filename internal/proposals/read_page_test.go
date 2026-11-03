package proposals

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestReadPageRejectsAnEmptyLimitOrBefore(t *testing.T) {
	tenant := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	for _, query := range []string{
		"?limit=",
		"?limit=0",
		"?before=",
		"?before=00000000-0000-0000-0000-000000000000",
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v1/proposals"+query, nil)
		if _, _, _, ok := readPage(recorder, request, func(*http.Request) (uuid.UUID, bool) {
			return tenant, true
		}); ok || recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: ok %v status %d", query, ok, recorder.Code)
		}
	}
}
