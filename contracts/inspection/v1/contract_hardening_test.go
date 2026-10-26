package inspectionv1

import (
	"strings"
	"testing"
)

func TestRequestRejectsUnsafeMetadata(t *testing.T) {
	base := Request{Method: "GET", Path: "/"}
	cases := map[string]Request{
		"header crlf": {
			Method: "GET", Path: "/",
			Headers: map[string][]string{"X-Test": {"a\r\nb"}},
		},
		"header invalid utf8": {
			Method: "GET", Path: "/",
			Headers: map[string][]string{"X-Test": {"a\xffb"}},
		},
		"authority userinfo": {
			Method: "GET", Path: "/", Authority: "user@example.com",
		},
		"authority space": {
			Method: "GET", Path: "/", Authority: "example.com evil",
		},
		"scheme ftp": {
			Method: "GET", Path: "/", Scheme: "ftp",
		},
		"request id control": {
			Method: "GET", Path: "/", RequestID: "bad\nid",
		},
		"path query delimiter": {
			Method: "GET", Path: "/a?b",
		},
		"path fragment": {
			Method: "GET", Path: "/a#b",
		},
		"path backslash": {
			Method: "GET", Path: `/a\b`,
		},
		"path space": {
			Method: "GET", Path: "/a b",
		},
		"path invalid utf8": {
			Method: "GET", Path: "/a\xffb",
		},
		"query crlf": {
			Method: "GET", Path: "/", Query: "a=\r\nb",
		},
		"method invalid utf8": {
			Method: "GE\xffT", Path: "/",
		},
		"body encoding without forwarding": {
			Method: "GET", Path: "/", BodyEncoding: "gzip",
		},
	}
	for name, request := range cases {
		if err := request.Validate(); err == nil {
			t.Errorf("%s: unexpectedly validated %+v", name, request)
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline request rejected: %v", err)
	}
}

func TestRequestBodyStateIsConsistent(t *testing.T) {
	cases := map[string]struct {
		request Request
		wantErr bool
	}{
		"absent": {
			request: Request{Method: "GET", Path: "/", BodyState: BodyStateAbsent},
		},
		"withheld": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateWithheld},
		},
		"forwarded empty": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateForwarded, BodyForwarded: true},
		},
		"forwarded body": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateForwarded, BodyForwarded: true, Body: []byte("x")},
		},
		"truncated": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateTruncated, BodyForwarded: true, BodyTruncated: true, Body: []byte("x")},
		},
		"absent with body": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateAbsent, BodyForwarded: true, Body: []byte("x")},
			wantErr: true,
		},
		"withheld with body": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateWithheld, Body: []byte("x")},
			wantErr: true,
		},
		"forwarded not marked": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateForwarded, Body: []byte("x")},
			wantErr: true,
		},
		"truncated not marked": {
			request: Request{Method: "POST", Path: "/", BodyState: BodyStateTruncated, BodyForwarded: true, Body: []byte("x")},
			wantErr: true,
		},
		"unknown state": {
			request: Request{Method: "POST", Path: "/", BodyState: "partial"},
			wantErr: true,
		},
	}
	for name, test := range cases {
		err := test.request.Validate()
		if test.wantErr && err == nil {
			t.Errorf("%s: unexpectedly validated", name)
		}
		if !test.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
	}
}

func TestDecisionSupportsChallengeResponse(t *testing.T) {
	decision := Decision{
		Action:          ActionChallenge,
		StatusCode:      401,
		Headers:         map[string]string{"WWW-Authenticate": `Basic realm="waf"`, "Location": "/login"},
		SetCookies:      []string{"cw_session=abc; Path=/; HttpOnly"},
		Body:            []byte("<html>verify</html>"),
		BodyContentType: "text/html; charset=utf-8",
	}
	if err := decision.Validate(); err != nil {
		t.Fatalf("challenge decision rejected: %v", err)
	}
	normalized := Decision{Action: ActionChallenge, Body: []byte("verify")}.Normalized()
	if normalized.StatusCode != 401 {
		t.Fatalf("normalized challenge status = %d", normalized.StatusCode)
	}
	if normalized.BodyContentType == "" {
		t.Fatal("normalized body content type is empty")
	}
}

func TestDecisionRejectsUnsafeResponseFields(t *testing.T) {
	cases := map[string]Decision{
		"header crlf": {
			Action:  ActionBlock,
			Headers: map[string]string{"X-Test": "a\r\nb"},
		},
		"header invalid name": {
			Action:  ActionBlock,
			Headers: map[string]string{"Bad Header": "x"},
		},
		"cookie crlf": {
			Action:     ActionChallenge,
			SetCookies: []string{"cw=1\r\nInjected: yes"},
		},
		"oversized body": {
			Action: ActionBlock,
			Body:   []byte(strings.Repeat("x", maxDecisionBodyBytes+1)),
		},
		"invalid content type": {
			Action:          ActionBlock,
			Body:            []byte("x"),
			BodyContentType: "text/html\r\nInjected: yes",
		},
		"too many cookies": {
			Action:     ActionChallenge,
			SetCookies: strings.Split(strings.Repeat("a=1|", maxSetCookies+1), "|")[:maxSetCookies+1],
		},
	}
	for name, decision := range cases {
		if err := decision.Validate(); err == nil {
			t.Errorf("%s: unexpectedly validated", name)
		}
	}
}
