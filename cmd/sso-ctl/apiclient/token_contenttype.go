package apiclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func (ck *checker) runT8eIfRequested(probeGrant string) (ok, skipped bool) {
	if !ck.expectFormOnly {
		return true, false
	}
	return ck.runT8e(probeGrant)
}

func (ck *checker) runT8e(probeGrant string) (ok, skipped bool) {
	if ck.doc == nil || ck.doc.TokenEndpoint == "" {
		fmt.Fprintln(os.Stderr, "check: T-8e skipped: advertised token_endpoint absent")
		return false, true
	}
	target := ck.doc.TokenEndpoint
	if err := validateAdvertisedURL(target); err != nil {
		fmt.Fprintf(os.Stderr, "content_type probe: token_endpoint %s: %s; row failed\n", redactURL(target), err.Error())
		fmt.Fprintln(os.Stdout, "content_type: FAIL")
		return false, false
	}
	passed := true
	for _, mediaType := range []string{contentTypeJSON, contentTypeTextPlain, ""} {
		if diagnostic := ck.checkFormRejection(target, mediaType, probeGrant); diagnostic != "" {
			fmt.Fprintln(os.Stderr, diagnostic)
			passed = false
		}
	}
	if passed {
		fmt.Fprintln(os.Stdout, "content_type: OK")
		return true, false
	}
	fmt.Fprintln(os.Stdout, "content_type: FAIL")
	return false, false
}

func (ck *checker) checkFormRejection(target, mediaType, probeGrant string) string {
	req, err := ck.formRejectionRequest(target, mediaType, probeGrant)
	if err != nil {
		return fmt.Sprintf("content_type probe (%s): %s", contentTypeLabel(mediaType), redactURL(err.Error()))
	}
	resp, err := probeClient(target).http.Do(req)
	if err != nil {
		return fmt.Sprintf("content_type probe (%s): %s", contentTypeLabel(mediaType), redactURL(err.Error()))
	}
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		status := resp.StatusCode
		_ = resp.Body.Close()
		return fmt.Sprintf("content_type probe (%s): status %d, expected 415", contentTypeLabel(mediaType), status)
	}
	body, err := ReadBody(resp)
	if err != nil {
		return fmt.Sprintf("content_type probe (%s): %s", contentTypeLabel(mediaType), err.Error())
	}
	if !isFormOnlyError(body) {
		return fmt.Sprintf("content_type probe (%s): status 415 did not return invalid_request", contentTypeLabel(mediaType))
	}
	return ""
}

func (ck *checker) formRejectionRequest(target, mediaType, probeGrant string) (*http.Request, error) {
	body := map[string]string{"grant_type": probeGrant}
	if ck.clientAuthMethod != clientAuthMethodBasic {
		body["client_id"] = ck.clientID
		body["client_secret"] = ck.clientSecret
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode probe: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(string(encoded)))
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerAccept, contentTypeJSON)
	if mediaType != "" {
		req.Header.Set(headerContentType, mediaType)
	}
	if ck.clientAuthMethod == clientAuthMethodBasic {
		req.SetBasicAuth(ck.clientID, ck.clientSecret)
	}
	return req, nil
}

func isFormOnlyError(body []byte) bool {
	var response struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(body, &response) == nil && response.Error == "invalid_request"
}

func contentTypeLabel(mediaType string) string {
	if mediaType == "" {
		return "missing Content-Type"
	}
	return mediaType
}
