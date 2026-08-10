package client

import (
	"bytes"
	"encoding/json"
)

// ResponseV2 is the v2 envelope. Unlike v1 it carries no sign field: the
// signature lives in the response headers.
type ResponseV2 struct {
	Status    int             `json:"status"`
	Msg       string          `json:"msg"`
	Data      json.RawMessage `json:"data"`
	DateTime  string          `json:"date_time"`
	TimeStamp int64           `json:"time_stamp"`
}

// isAbsentJsonData reports whether a raw data field carries no usable object.
//
// The platform emits "data":[] on every business error, because its failure
// helper passes an empty slice as the data value. Decoding that array straight
// into a struct fails, which would turn every business status into an opaque
// decode error and lose the status entirely. An explicit null or a missing field
// are treated the same way.
func isAbsentJsonData(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return true
	}
	// These data fields are always JSON objects, so anything else means "no
	// data". Restricting this to arrays would let a scalar data value surface as
	// a raw decode error instead of the business status.
	return trimmed[0] != '{'
}

// dataCarrier reports whether a decoded response holds a data object. The client
// uses it to turn a success with no data into an error rather than handing back a
// nil pointer.
type dataCarrier interface {
	hasData() bool
}

// Asserted at compile time so a response type cannot silently omit hasData().
// Without this, adding a type with a pointer Data field and no method would
// reinstate the nil pointer risk with no build or test failure.
var (
	_ dataCarrier = TrVaspListResponse{}
	_ dataCarrier = TrVerifyAddressResponse{}
	_ dataCarrier = TrQueryTransferResponse{}
	_ dataCarrier = TrTransferResponse{}
	_ dataCarrier = TrPostTransferResponse{}
	_ dataCarrier = TrReceiveAuditResponse{}
	_ dataCarrier = TrRateResponse{}
	_ dataCarrier = TrHotWalletResponse{}
)

// decodeDataObject decodes the envelope and then the data object, leaving out
// nil when the response carried none.
//
// Every response whose data is an object goes through here rather than writing
// its own UnmarshalJSON, so none of them can omit the clearing step below.
func decodeDataObject[T any](raw []byte, envelope *ResponseV2, out **T) error {
	// Cleared first so decoding into a reused value cannot leave data from the
	// previous message behind when this one carries none.
	*out = nil
	hasData, err := decodeEnvelope(raw, envelope)
	if err != nil || !hasData {
		return err
	}
	data := new(T)
	if err := json.Unmarshal(envelope.Data, data); err != nil {
		return err
	}
	*out = data
	return nil
}

// decodeEnvelope unmarshals the shared envelope and reports whether the data
// field holds an object worth decoding.
func decodeEnvelope(raw []byte, envelope *ResponseV2) (hasData bool, err error) {
	// Cleared first because encoding/json leaves an absent field untouched, so
	// decoding into a reused value would otherwise keep the previous raw data.
	envelope.Data = nil
	if err := json.Unmarshal(raw, envelope); err != nil {
		return false, err
	}
	return !isAbsentJsonData(envelope.Data), nil
}

// TrVaspListResponse carries one page of the VASP directory.
//
// Data is nil when the platform sent no data object, which is the case for every
// business error. Check the error before dereferencing it.
type TrVaspListResponse struct {
	ResponseV2
	Data *TrVaspListData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrVaspListResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrVaspListResponse) hasData() bool { return r.Data != nil }

// TrVaspListData is a page of directory entries.
//
// Total counts everything matching the query, not the page, so it is what to
// drive paging off. Items is empty rather than null when nothing matches.
type TrVaspListData struct {
	Items    []TrVaspItem `json:"items"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
	Total    int64        `json:"total"`
}

// TrVaspItem is one directory entry.
//
// Provider service health is not part of it. Status is the platform's own
// approval state and means something different; this endpoint reads a local
// snapshot, so a health value would be stale, and "reachable" reads too easily as
// "cleared to trade". Real availability only shows up when a request is made —
// TrTransfer answers 617 with the provider's errorType.
type TrVaspItem struct {
	// VaspId is the platform VASP id, formatted {provider}:{provider_vasp_id},
	// for example code:coinone. Use this everywhere a request takes a VASP id.
	VaspId    string `json:"vasp_id"`
	Name      string `json:"name"`
	LegalName string `json:"legal_name"`
	// CountryCode is the country of registration, ISO 3166-1 alpha-2.
	CountryCode string `json:"country_code"`
	// Status is the platform's local approval state, and the only field here
	// bearing on whether a transfer can go out. Only ACTIVE entries are returned.
	//
	// It is still not a compliance clearance: per merchant and per jurisdiction
	// approval, and per VASP due diligence, are separate decisions.
	Status string `json:"status"`
	// Provider names the network this entry came from, currently always "code".
	Provider string `json:"provider"`
	// ProviderVaspId is the provider's own id, the part after the colon in
	// VaspId. Informational; requests take VaspId.
	ProviderVaspId string `json:"provider_vasp_id"`
	// AllianceName matters for payload construction: different alliances require
	// different IVMS101 fields, and the platform cannot check them for you
	// because it never decrypts the payload. A missing field surfaces as a 422
	// from the counterparty, at which point the platform cannot fix it either.
	AllianceName string `json:"alliance_name"`
	// PublicKeys is empty rather than null when the entry has no usable key.
	PublicKeys []TrVaspKey `json:"public_keys"`
}

// TrVaspKey is one published Ed25519 public key.
//
// Cache these, but keep the exact base64 string: it is case sensitive and must
// be sent back byte for byte alongside any ciphertext it encrypted. During a
// key rotation more than one key can be valid at once; pick one and echo that
// same one.
type TrVaspKey struct {
	Value string `json:"value"`
	// ExpiresAt is RFC3339, and absent when the provider published no expiry.
	ExpiresAt string `json:"expires_at"`
}

// TrVerifyAddressResponse answers either branch of verifyAddress.
//
// Data is nil when the platform sent no data object, which is the case for every
// business error. Check the error before dereferencing it.
type TrVerifyAddressResponse struct {
	ResponseV2
	Data *TrVerifyAddressData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrVerifyAddressResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrVerifyAddressResponse) hasData() bool { return r.Data != nil }

// TrVerifyAddressData is the verifyAddress result.
type TrVerifyAddressData struct {
	// RequestId is set on the lookup branch, and can be passed to
	// TrTransferRequest.SearchRequestId for traceability.
	RequestId string `json:"request_id"`
	// Result is ResultValid or ResultInvalid.
	Result string `json:"result"`
	// ReasonType is one of the Reason constants; a lookup miss reports
	// ReasonNotFoundAddress.
	ReasonType    string `json:"reason_type"`
	ReasonMessage string `json:"reason_message"`
	// BeneficiaryVaspId can be used directly as TrTransferRequest.BeneficiaryVaspId.
	// On the synchronous branch the platform echoes the requested value when the
	// counterparty did not return one.
	BeneficiaryVaspId string `json:"beneficiary_vasp_id"`
	// HotWalletAddress is the beneficiary's hot wallet address, returned when
	// the platform knows it.
	HotWalletAddress string `json:"hot_wallet_address"`
}

// TrQueryTransferResponse answers a txid lookup.
//
// Data is nil when the platform sent no data object, which includes the common
// 618 "still running" case. Check the error before dereferencing it.
type TrQueryTransferResponse struct {
	ResponseV2
	Data *TrQueryTransferData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrQueryTransferResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrQueryTransferResponse) hasData() bool { return r.Data != nil }

// TrQueryTransferData is the txid lookup result.
type TrQueryTransferData struct {
	// RequestId identifies the lookup task. Kept for troubleshooting and logs;
	// TrPostTransfer does not take it — locate that call by txid and coin.
	RequestId string `json:"request_id"`
	// OriginatorVaspId is the VASP that sent the deposit. This resolves a sender,
	// where verifyAddress resolves a beneficiary — hence the different name.
	OriginatorVaspId string `json:"originator_vasp_id"`
	// Result is ResultValid or ResultInvalid.
	Result string `json:"result"`
	// ReasonType on a miss is ReasonNotFoundTxid, ReasonNonUniqueResult or
	// ReasonUnknown.
	ReasonType    string `json:"reason_type"`
	ReasonMessage string `json:"reason_message"`
	// OriginatorPubKey is the key to encrypt the TrPostTransfer payload for. It
	// is the latest expiring key the platform holds for that VASP.
	OriginatorPubKey string `json:"originator_public_key"`
	// OriginatorPubKeys is every key the platform holds, most recent first. It
	// exists for key rotation: if the counterparty cannot decrypt what was
	// encrypted for OriginatorPubKey, retry down this list rather than guessing.
	OriginatorPubKeys []string `json:"originator_public_keys"`
}

// TrTransferResponse answers a withdrawal authorisation.
//
// Data is nil when the platform sent no data object, which is the case for every
// business error. Check the error before dereferencing it.
type TrTransferResponse struct {
	ResponseV2
	Data *TrTransferData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrTransferResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrTransferResponse) hasData() bool { return r.Data != nil }

// TrTransferData is the transfer result.
//
// Result alone is enough to decide whether to proceed. RouteDecision explains
// why, and is only needed to distinguish an actual refusal by the counterparty
// from the platform holding the transfer for review.
type TrTransferData struct {
	TransferId string `json:"transfer_id"`
	// RouteDecision is RouteDecisionTrCode, RouteDecisionPass or
	// RouteDecisionManual. Only TR_CODE means an authorisation was actually sent.
	RouteDecision string `json:"route_decision"`
	// Result is ResultVerified or ResultDenied, and nothing else. PASS reports
	// verified; MANUAL reports denied with ReasonLackOfInformation, which is
	// fail-closed and never a release.
	Result string `json:"result"`
	// ReasonType is one of the Reason constants. Platform internal codes and
	// non-standard provider codes are folded into ReasonUnknown, with the detail
	// in ReasonMessage, so there is no need to branch on unknown values.
	ReasonType    string `json:"reason_type"`
	ReasonMessage string `json:"reason_message"`
	// BeneficiaryVasp is the counterparty's optional override of the
	// beneficiaryVasp object, usually null. When present it takes precedence over
	// the matching content inside Payload. The platform passes the JSON through
	// without parsing it.
	BeneficiaryVasp json.RawMessage `json:"beneficiary_vasp"`
	// Payload is the counterparty's IVMS101 ciphertext, passed through
	// undecrypted. Decrypt it with your own private key and the counterparty's
	// public key.
	Payload string `json:"payload"`
}

// TrPostTransferResponse answers a supplementary data submission.
//
// Data is nil when the platform sent no data object, which is the case for every
// business error. Check the error before dereferencing it.
type TrPostTransferResponse struct {
	ResponseV2
	Data *TrPostTransferData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrPostTransferResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrPostTransferResponse) hasData() bool { return r.Data != nil }

// TrPostTransferData is the postTransfer result.
type TrPostTransferData struct {
	// TransferId is the platform-local id for this supplementary submission.
	// Reconcile on it; relate back to the prior lookup with the request's txid.
	TransferId string `json:"transfer_id"`
	// Result is ResultNormal or ResultError, the CodeVASP pair.
	Result        string `json:"result"`
	ReasonType    string `json:"reason_type"`
	ReasonMessage string `json:"reason_message"`
	// OriginatorVaspId is the sending VASP the lookup resolved.
	OriginatorVaspId string `json:"originator_vasp_id"`
	// Coin and Contract are the platform coin and chain names, matching what
	// requests take — not the provider's currency and network.
	Coin          string `json:"coin"`
	Contract      string `json:"contract"`
	Amount        string `json:"amount"`
	TradePrice    string `json:"trade_price"`
	TradeCurrency string `json:"trade_currency"`
	// IsExceedingThreshold is converted from the string CodeVASP returns; an
	// unparseable value reports false and is logged platform side rather than
	// failing the submission.
	IsExceedingThreshold bool `json:"is_exceeding_threshold"`
	// Payload is the ciphertext the counterparty supplied. Decrypt it yourself.
	Payload string `json:"payload"`
}

// TrReceiveAuditResponse answers a deposit audit submission.
type TrReceiveAuditResponse struct {
	ResponseV2
	Data *TrReceiveAuditData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrReceiveAuditResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrReceiveAuditResponse) hasData() bool { return r.Data != nil }

// TrReceiveAuditData is the receiveAudit result.
type TrReceiveAuditData struct {
	// Result is "normal" or "error".
	Result string `json:"result"`
	// ReasonType is set when Result is "error".
	ReasonType string `json:"reason_type"`
	// ReasonMessage gives details when Result is "error".
	ReasonMessage string `json:"reason_message"`
}

// TrRateResponse answers a rate query.
type TrRateResponse struct {
	ResponseV2
	Data *TrRateData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrRateResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrRateResponse) hasData() bool { return r.Data != nil }

// TrRateData is the rate query result.
type TrRateData struct {
	// Coin is the platform coin name.
	Coin string `json:"coin"`
	// FiatCode is the fiat currency code.
	FiatCode string `json:"fiat_code"`
	// Source is the price source, e.g. "cbc" or "upbit".
	Source string `json:"source"`
	// Price is the coin-to-fiat exchange rate as a decimal string.
	Price string `json:"price"`
}

// TrHotWalletResponse answers a hot wallet address query.
type TrHotWalletResponse struct {
	ResponseV2
	Data *TrHotWalletData `json:"data"`
}

// UnmarshalJSON decodes the envelope, leaving Data nil when there is no object.
func (r *TrHotWalletResponse) UnmarshalJSON(raw []byte) error {
	return decodeDataObject(raw, &r.ResponseV2, &r.Data)
}

func (r TrHotWalletResponse) hasData() bool { return r.Data != nil }

// TrHotWalletData is the hot wallet address result.
type TrHotWalletData struct {
	// Address is the platform hot wallet address for the queried coin.
	Address string `json:"address"`
}
