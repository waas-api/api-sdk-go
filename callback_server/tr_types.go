package callback_server

import "encoding/json"

// Relative paths of the six endpoints a merchant exposes. They are appended to
// the webhook base URL registered with the platform.
//
// Suggested build order: signature first, then transferResult, then the four
// inbound forwards. Only signature is needed before outbound withdrawals can
// work; the others carry real traffic once the inbound service is live.
const (
	TrPathSignature      = "/v2/travel_rule/signature"
	TrPathVerifyAddress  = "/v2/travel_rule/callback/verifyAddress"
	TrPathTransfer       = "/v2/travel_rule/callback/transfer"
	TrPathTransferResult = "/v2/travel_rule/callback/transferResult"
	TrPathPostTransfer   = "/v2/travel_rule/callback/postTransfer"
	TrPathHealth         = "/v2/travel_rule/callback/health"
)

// Inbound coin mapping.
//
// Every coin field in these callbacks is the platform coin name, the same form
// the outbound API takes — usdt_trc20, not USDT. The counterparty sends the
// provider's currency and network (USDT plus TRON); the platform resolves that
// to a single platform coin before forwarding, and maps the coin in a
// postTransfer reply back the other way before answering the counterparty.
//
// No callback carries a network field. The platform coin name already identifies
// the chain, so there is nothing to assemble: a bare USDT could not distinguish
// TRC20 from ERC20 from BEP20.
//
// When the platform has no mapping for the coin the counterparty named, it
// refuses without calling the merchant at all: transfer answers denied and
// verifyAddress answers invalid, both with NOT_SUPPORTED_SYMBOL. So a callback
// arriving here always has a coin that exists in the platform's tables.

// Result values a merchant may return. The platform rejects anything else and
// falls back to a denial with reason type UNKNOWN, so use these constants.
const (
	// Address verification.
	TrResultValid   = "valid"
	TrResultInvalid = "invalid"
	// Transfer authorisation.
	TrResultVerified = "verified"
	TrResultDenied   = "denied"
	// Transfer result and supplementary data.
	TrResultNormal = "normal"
	TrResultError  = "error"
)

// TrReasonUnknown is the shared fallback reason type. It covers merchant side
// faults.
//
// Do not report a merchant side fault as a lack of information: that tells the
// counterparty to supply more data when the real problem is local.
const TrReasonUnknown = "UNKNOWN"

// TrSignatureRequest asks the merchant to sign bytes for an outbound CodeVASP
// request.
//
// This exists because the merchant's Ed25519 private key is never given to the
// platform. It is called before every outbound request, including each poll of
// an in-flight VASP lookup, so it sits on the critical path and needs to be
// fast and highly available. Around 100 concurrent lookups produce roughly 10
// calls per second.
type TrSignatureRequest struct {
	// VaspId is the merchant's own platform VASP id.
	VaspId string `json:"vasp_id"`
	// Message is base64 of the exact bytes to sign. Decode it and apply
	// Ed25519; do not assemble datetime, body or nonce yourself.
	Message string `json:"message"`
	// Operation names the CodeVASP operation. It is for the merchant's audit
	// log only and is not covered by the signature.
	Operation string `json:"operation"`
}

// TrSignatureResponse returns the base64 Ed25519 signature.
type TrSignatureResponse struct {
	Signature string `json:"signature"`
}

// TrVerifyAddressCallbackRequest asks whether an address belongs to one of the
// merchant's customers. It arrives when a counterparty is checking a
// destination before sending.
type TrVerifyAddressCallbackRequest struct {
	VaspId string `json:"vasp_id"`
	// Coin is the platform coin name, the same form outbound requests take (for
	// example usdt_trc20). The counterparty sends a provider currency and
	// network, which the platform maps before forwarding, so this can be looked
	// up in your own coin table directly. See the package note on inbound coin
	// mapping for why there is no network field.
	Coin string `json:"coin"`
	// OriginatorVaspId identifies the asking VASP.
	OriginatorVaspId string `json:"originator_vasp_id"`
	// OriginatorPublicKey is the key the platform actually verified the inbound
	// request against, taken from its local cache. Use this to decrypt Payload:
	// it is trusted, unlike the key in the raw inbound header.
	OriginatorPublicKey string `json:"originator_public_key"`
	// Payload is the base64 ciphertext holding the address to check. The
	// address is inside the encrypted IVMS101, so it has to be decrypted before
	// it can be looked up.
	Payload string `json:"payload"`
}

// TrVerifyAddressCallbackResponse answers with TrResultValid or TrResultInvalid.
type TrVerifyAddressCallbackResponse struct {
	Result        string `json:"result"`
	ReasonType    string `json:"reason_type,omitempty"`
	ReasonMessage string `json:"reason_message,omitempty"`
}

// TrTransferCallbackRequest asks the merchant to authorise an incoming
// transfer. The counterparty is waiting on this answer before it releases funds.
type TrTransferCallbackRequest struct {
	VaspId     string `json:"vasp_id"`
	TransferId string `json:"transfer_id"`
	// Coin is the platform coin name, mapped from the counterparty's currency and
	// network. See the package note on inbound coin mapping.
	Coin   string `json:"coin"`
	Amount string `json:"amount"`
	// HistoricalCost may be absent.
	HistoricalCost string `json:"historical_cost"`
	// TradePrice is the fiat total, not a unit price.
	TradePrice           string `json:"trade_price"`
	TradeCurrency        string `json:"trade_currency"`
	IsExceedingThreshold bool   `json:"is_exceeding_threshold"`
	// OriginatingVasp is the raw IVMS101 VASP object, passed through as sent.
	OriginatingVasp  json.RawMessage `json:"originating_vasp,omitempty"`
	OriginatorVaspId string          `json:"originator_vasp_id"`
	// OriginatorPublicKey is the verified key to decrypt Payload with, and the
	// key to encrypt the reply payload for.
	OriginatorPublicKey string `json:"originator_public_key"`
	Payload             string `json:"payload"`
	BeneficiaryAddress  string `json:"beneficiary_address,omitempty"`
	Tag                 string `json:"tag,omitempty"`
}

// TrTransferCallbackResponse answers with TrResultVerified or TrResultDenied,
// plus the merchant's own encrypted IVMS101.
type TrTransferCallbackResponse struct {
	Result        string `json:"result"`
	ReasonType    string `json:"reason_type,omitempty"`
	ReasonMessage string `json:"reason_message,omitempty"`
	// Payload is the merchant's IVMS101, encrypted for the originator.
	Payload string `json:"payload,omitempty"`
	// BeneficiaryVasp optionally carries the IVMS101 beneficiaryVasp object.
	BeneficiaryVasp json.RawMessage `json:"beneficiary_vasp,omitempty"`
	// BeneficiaryAddress optionally echoes the resolved address.
	BeneficiaryAddress string `json:"beneficiary_address,omitempty"`
}

// TrTransferResultCallbackRequest reports the final outcome of a transfer.
//
// Two different flows deliver to this one path, and they do not carry the same
// fields. Use IsOutboundAuthorization to tell them apart:
//
//   - An inbound on-chain result, forwarded from the counterparty. Status is
//     confirmed with a Txid, or canceled. VaspId is set; Result is empty.
//   - The authorisation conclusion for one of the merchant's own withdrawals,
//     following a transfer call. Result is verified or denied and Payload holds
//     the counterparty's identity data. Status, VaspId, Txid and Vout are empty.
//
// This is the one callback with a defined idempotency rule: the same
// transfer_id, status, txid and vout must always produce the same answer. It is
// also the only one the platform retries more than once, so handle repeats.
type TrTransferResultCallbackRequest struct {
	// VaspId is set on inbound results only.
	VaspId     string `json:"vasp_id"`
	TransferId string `json:"transfer_id"`
	// Status is confirmed when reporting an on-chain result, or canceled when
	// ending a transfer. Empty on an outbound authorisation conclusion.
	Status string `json:"status"`
	// Txid is present when reporting a completed inbound transfer.
	Txid string `json:"txid,omitempty"`
	Vout string `json:"vout,omitempty"`
	// Result is TrResultVerified or TrResultDenied on an outbound authorisation
	// conclusion, and empty on an inbound result.
	Result        string `json:"result,omitempty"`
	ReasonType    string `json:"reason_type,omitempty"`
	ReasonMessage string `json:"reason_message,omitempty"`
	// Payload is the counterparty's IVMS101 ciphertext, present on an outbound
	// authorisation conclusion. Decrypt it with the beneficiary public key used
	// for the transfer.
	Payload string `json:"payload,omitempty"`
}

// IsOutboundAuthorization reports whether this delivery is the authorisation
// conclusion for one of the merchant's own withdrawals rather than an inbound
// on-chain result.
//
// The two are distinguished by which fields are populated: only the outbound
// conclusion carries Result, and only the inbound result carries Status.
func (r TrTransferResultCallbackRequest) IsOutboundAuthorization() bool {
	return r.Result != "" && r.Status == ""
}

// TrTransferResultCallbackResponse answers with TrResultNormal or TrResultError.
type TrTransferResultCallbackResponse struct {
	Result        string `json:"result"`
	ReasonType    string `json:"reason_type,omitempty"`
	ReasonMessage string `json:"reason_message,omitempty"`
}

// TrPostTransferCallbackRequest carries the identity data a counterparty
// supplied for a deposit that had already settled.
type TrPostTransferCallbackRequest struct {
	VaspId             string `json:"vasp_id"`
	TransferId         string `json:"transfer_id"`
	Txid               string `json:"txid"`
	BeneficiaryAddress string `json:"beneficiary_address"`
	Tag                string `json:"tag,omitempty"`
	// BeneficiaryVaspId identifies the VASP that sent this data.
	BeneficiaryVaspId string `json:"beneficiary_vasp_id"`
	// BeneficiaryPublicKey is the verified key to decrypt Payload with.
	BeneficiaryPublicKey string `json:"beneficiary_public_key"`
	Payload              string `json:"payload"`
}

// TrPostTransferCallbackResponse answers with TrResultNormal or TrResultError.
type TrPostTransferCallbackResponse struct {
	Result        string `json:"result"`
	ReasonType    string `json:"reason_type,omitempty"`
	ReasonMessage string `json:"reason_message,omitempty"`
	// Payload optionally carries the merchant's own encrypted data.
	Payload string `json:"payload,omitempty"`
	// Coin is the platform coin name, the same form everywhere else. The platform
	// maps it back to the provider's currency before answering the counterparty,
	// so there is no need to deal in provider terms here.
	Coin   string `json:"coin,omitempty"`
	Amount string `json:"amount,omitempty"`
	// HistoricalCost, TradePrice, TradeCurrency and IsExceedingThreshold are
	// optional echoes of the transfer details.
	HistoricalCost       string `json:"historical_cost,omitempty"`
	TradePrice           string `json:"trade_price,omitempty"`
	TradeCurrency        string `json:"trade_currency,omitempty"`
	IsExceedingThreshold *bool  `json:"is_exceeding_threshold,omitempty"`
}

// TrHealthCallbackRequest is the platform's availability probe.
type TrHealthCallbackRequest struct {
	VaspId string `json:"vasp_id"`
}

// TrHealthCallbackResponse reports health.
//
// The check must include whether the signing dependency is reachable.
// Otherwise the platform only discovers a broken signer when it tries to make a
// real request, by which point a compliance exchange is already in flight.
type TrHealthCallbackResponse struct {
	// Healthy false makes the handler answer HTTP 503.
	Healthy bool   `json:"-"`
	Status  string `json:"status,omitempty"`
	Msg     string `json:"msg,omitempty"`
}
