package inspectionv1

import "testing"

func TestRequestRejectsMethodWhitespace(t *testing.T) {
	for _, method := range []string{" GET", "GET ", "G ET", "GET\t"} {
		request := Request{Method: method, Path: "/"}
		if err := request.Validate(); err == nil {
			t.Errorf("method %q unexpectedly validated", method)
		}
	}
}

func TestDecisionRejectsNonClientBlockStatus(t *testing.T) {
	for _, status := range []int{399, 500, 503} {
		decision := Decision{Action: ActionBlock, StatusCode: status}
		if err := decision.Validate(); err == nil {
			t.Errorf("block status %d unexpectedly validated", status)
		}
	}
}
