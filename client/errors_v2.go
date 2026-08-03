package client

import (
	"errors"
	"fmt"
)

// Business status codes returned in the v2 response envelope.
//
// A non-200 status is not necessarily a failure of the request: 618 in
// particular is a normal intermediate state.
const (
	// StatusOk means the call succeeded.
	StatusOk = 200

	// Signature layer, from the v2 verification middleware.
	StatusSignatureMalformed   = 601 // missing header, or bad nonce charset/length
	StatusTimestampOutOfWindow = 602
	StatusNonceReused          = 603
	StatusAlgorithmUnsupported = 604
	StatusSignatureInvalid     = 605
	StatusAntiReplayDown       = 606

	// Travel Rule layer.
	StatusTrNotEnabled = 610 // merchant has no active Travel Rule config
	StatusVaspInvalid  = 611 // vasp id unknown or not locally approved
	// StatusCoinNotMapped means the coin has no usable Travel Rule mapping. It
	// also covers an ambiguous mapping, which is a platform side configuration
	// fault a merchant cannot correct by changing the request.
	StatusCoinNotMapped       = 612
	StatusInvalidParameter    = 613 // conditional field missing, or bad format
	StatusProviderDown        = 614
	StatusResourceNotFound    = 615 // transfer/request id unknown or not yours
	StatusSignatureCallback   = 616 // the platform could not get a signature from you
	StatusProviderError       = 617 // CodeVASP returned a structured error
	StatusSearchProcessing    = 618 // lookup still running, retry the same call
	StatusVaspKeyCacheMissing = 619
)

// ApiErrorV2 is a non-200 business status from the v2 API.
//
// The status is preserved rather than flattened into a string so callers can
// branch on it. Msg often carries the underlying provider errorType, which is
// what identifies the actual problem.
type ApiErrorV2 struct {
	Status int
	Msg    string
}

func (e *ApiErrorV2) Error() string {
	return fmt.Sprintf("api error, status %d, %s", e.Status, e.Msg)
}

// StatusCode reports the business status of err, or 0 if err is not an
// *ApiErrorV2.
func StatusCode(err error) int {
	var apiErr *ApiErrorV2
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// IsSearchProcessing reports whether err is status 618, meaning the VASP lookup
// has been accepted but has no result yet.
//
// This is the expected outcome of a first call, not a fault: the platform waits
// only a few seconds in the request while the provider advises polling no more
// often than every 10 seconds. Retry the same call with the same parameters
// after at least 10 seconds.
func IsSearchProcessing(err error) bool {
	return StatusCode(err) == StatusSearchProcessing
}

// IsRetryable reports whether retrying the same call could succeed.
//
// Signature callback failures (616) mean the request never left the platform,
// and anti replay outages (606) are transient infrastructure faults. For 617
// the provider's own error type decides, so it is not included here; read Msg.
func IsRetryable(err error) bool {
	switch StatusCode(err) {
	case StatusSearchProcessing, StatusSignatureCallback, StatusAntiReplayDown:
		return true
	default:
		return false
	}
}
