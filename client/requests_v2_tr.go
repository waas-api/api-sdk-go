package client

// Travel Rule request paths. They are part of the string-to-sign, so they must
// match what is sent on the wire byte for byte.
const (
	pathTrVaspList      path = "/travelRule/vaspList"
	pathTrVerifyAddress path = "/travelRule/verifyAddress"
	pathTrTransfer      path = "/travelRule/transfer"
	pathTrQueryTransfer path = "/travelRule/queryTransfer"
	pathTrPostTransfer  path = "/travelRule/postTransfer"
	pathTrReceiveAudit  path = "/travelRule/receiveAudit"
	pathTrRate          path = "/travelRule/rate"
	pathTrHotWallet     path = "/address/hotWallet"
)

// Beneficiary type declarations. The merchant declares what the receiving side
// is; the platform cannot infer it, because "a VASP that is not on the CODE
// network" and "a self hosted wallet" are indistinguishable in a lookup result.
//
// Omitting the field is treated as UNKNOWN, which routes to MANUAL. That is the
// fail-safe direction: defaulting to VASP would send requests into the main flow
// only to stall on NOT_FOUND, and defaulting to SELF_HOSTED would amount to
// defaulting to release.
const (
	BeneficiaryTypeVasp       = "VASP"
	BeneficiaryTypeSelfHosted = "SELF_HOSTED"
	BeneficiaryTypeUnknown    = "UNKNOWN"
)

// Routing decisions returned on a transfer.
const (
	// RouteDecisionTrCode means authorisation was sent to the CODE network.
	RouteDecisionTrCode = "TR_CODE"
	// RouteDecisionPass means released without a Travel Rule exchange, with a
	// record kept of why.
	RouteDecisionPass = "PASS"
	// RouteDecisionManual means the transfer is held for manual review.
	RouteDecisionManual = "MANUAL"
)

// Business result values.
//
// A transfer answers only verified or denied: a PASS route reports verified, and
// MANUAL reports denied. Branching on Result alone is safe, and RouteDecision
// explains why.
const (
	ResultValid    = "valid"
	ResultInvalid  = "invalid"
	ResultVerified = "verified"
	ResultDenied   = "denied"
	// Supplementary data submission uses the CodeVASP pair instead.
	ResultNormal = "normal"
	ResultError  = "error"
)

// Reason types that can appear in a response. The platform folds its own
// internal codes and any non-standard provider code into ReasonUnknown, so this
// is the complete set; the detail is in ReasonMessage.
//
// Do not switch on values outside this list.
const (
	ReasonNotFoundAddress   = "NOT_FOUND_ADDRESS"
	ReasonNotFoundTxid      = "NOT_FOUND_TXID"
	ReasonNotSupportedCoin  = "NOT_SUPPORTED_SYMBOL"
	ReasonNotKycUser        = "NOT_KYC_USER"
	ReasonNameMismatched    = "INPUT_NAME_MISMATCHED"
	ReasonDobMismatched     = "DOB_MISMATCHED"
	ReasonSanctionList      = "SANCTION_LIST"
	ReasonLackOfInformation = "LACK_OF_INFORMATION"
	ReasonNonUniqueResult   = "ALLIANCE_DATA_NON_UNIQUE_RESULT"
	ReasonUnknown           = "UNKNOWN"
)

// Paging bounds for TrVaspListRequest. A page size above MaxVaspPageSize is
// refused with status 613, not clamped.
const (
	DefaultVaspPageSize = 50
	MaxVaspPageSize     = 200
)

// TrVaspListRequest fetches a page of the VASP directory. Every field is
// optional; an empty request returns the first page.
//
// The directory is the platform's locally approved subset of what the provider
// reports as reachable. A hit is not a compliance clearance: per merchant and
// per jurisdiction approval, and per VASP due diligence, are separate.
type TrVaspListRequest struct {
	// VaspId matches one entry exactly, in platform {provider}:{provider_vasp_id}
	// form.
	VaspId string `json:"vasp_id,omitempty"`
	// Keyword matches the display or legal name, at most 100 characters.
	Keyword string `json:"keyword,omitempty"`
	// Page is 1 based. Zero is omitted from the request, so the platform applies
	// its default of 1.
	Page int `json:"page,omitempty"`
	// PageSize defaults to DefaultVaspPageSize when omitted. Values above
	// MaxVaspPageSize are refused with status 613.
	PageSize int `json:"page_size,omitempty"`
}

// TrVerifyAddressRequest either verifies an address against a known VASP or
// looks up which VASP an address belongs to.
//
// BeneficiaryVaspId, Payload and BeneficiaryPublicKey are conditionally required
// as a group: supply all three to verify synchronously against that VASP, or
// none of them to run a lookup. Supplying only some returns business status 613
// rather than guessing the intent.
type TrVerifyAddressRequest struct {
	OriginatorVaspId  string `json:"originator_vasp_id"`
	BeneficiaryVaspId string `json:"beneficiary_vasp_id,omitempty"`
	// Coin is the platform coin name, which already identifies the chain (for
	// example usdt_trc20). There is no network field: the platform resolves the
	// network from its own coin mapping.
	Coin    string `json:"coin"`
	Address string `json:"address"`
	// Tag is the memo or tag for coins that use one. The platform combines it
	// with the address as "address:tag" when running a wallet lookup.
	Tag string `json:"tag,omitempty"`
	// Payload is the base64 NaCl box ciphertext. Set it together with
	// BeneficiaryPublicKey; EncryptedPayload.ApplyToVerifyAddress does both.
	Payload string `json:"payload,omitempty"`
	// BeneficiaryPublicKey must be the very same base64 key used to encrypt
	// Payload, byte for byte and case preserved.
	BeneficiaryPublicKey string `json:"beneficiary_public_key,omitempty"`
}

// TrQueryTransferRequest looks up the originating VASP of a deposit by txid.
//
// The own VASP comes from the merchant's platform configuration, so there is no
// originator_vasp_id field. There is no network field either: the coin name
// itself carries the chain (for example usdt_trc20), which is enough to resolve
// a single active mapping.
type TrQueryTransferRequest struct {
	Coin string `json:"coin"`
	Txid string `json:"txid"`
	// BeneficiaryAddress is optional. When omitted the platform falls back to
	// the deposit record for this coin and txid; if it cannot find an address
	// it returns business status 615.
	BeneficiaryAddress string `json:"beneficiary_address,omitempty"`
	// Tag is the memo or tag, which should be sent explicitly for coins that
	// use one (XRP, for example).
	Tag string `json:"tag,omitempty"`
}

// TrTransferRequest submits a withdrawal for Travel Rule handling.
//
// Every call is recorded, including those that route to PASS or MANUAL: in an
// audit, "assessed and found not to require an exchange" must be
// distinguishable from "never assessed".
type TrTransferRequest struct {
	OriginatorVaspId string `json:"originator_vasp_id"`
	// BeneficiaryVaspId is required when BeneficiaryType is VASP and the
	// threshold is exceeded.
	BeneficiaryVaspId string `json:"beneficiary_vasp_id,omitempty"`
	// SearchRequestId optionally links this transfer to the address lookup task
	// it came from, for traceability.
	SearchRequestId string `json:"search_request_id,omitempty"`
	ShopOrderId     string `json:"shop_order_id,omitempty"`
	// Coin is the platform coin name, which already identifies the chain (for
	// example usdt_trc20). There is no network field: the platform resolves the
	// network from its own coin mapping.
	Coin string `json:"coin"`
	// Amount is a decimal string, at most 30 integer and 8 fractional digits.
	// Never send a JSON number: float formatting differs between languages and
	// the signature covers the exact bytes.
	Amount string `json:"amount"`
	// TradePrice is the fiat total for the transfer, not a unit price.
	TradePrice    string `json:"trade_price"`
	TradeCurrency string `json:"trade_currency"`
	// Payload is required only when the route resolves to TR_CODE.
	Payload string `json:"payload,omitempty"`
	// BeneficiaryPublicKey must be the very same base64 key used to encrypt
	// Payload. Use EncryptedPayload.ApplyToTransfer to set both together.
	BeneficiaryPublicKey string `json:"beneficiary_public_key,omitempty"`
	OriginatorAddress    string `json:"originator_address"`
	BeneficiaryAddress   string `json:"beneficiary_address"`
	Tag                  string `json:"tag,omitempty"`
	// OriginatorCountryCode is the KYC country of the sending wallet's owner,
	// ISO 3166-1 alpha-2. The platform records it without validating ownership.
	OriginatorCountryCode string `json:"originator_country_code,omitempty"`
	// IsExceedingThreshold is the minimal threshold declaration. Supply either
	// this or Threshold; when both are set, Threshold wins.
	//
	// It is a pointer so that false and "not supplied" stay distinguishable.
	// Conflating them would let a missing declaration read as "under the
	// threshold", which is a compliance decision nobody made.
	IsExceedingThreshold *bool `json:"is_exceeding_threshold,omitempty"`
	// Threshold is the fuller declaration, and the recommended one. A lone
	// boolean cannot answer "under which jurisdiction, which rule version, and at
	// what exchange rate was this judged", so the platform marks records that
	// carry only the boolean as having incomplete evidence.
	//
	// Use SetThreshold or SetThresholdExceeded rather than assigning either form
	// directly, so only one of the two ends up on the wire.
	Threshold *TrThresholdDeclaration `json:"threshold,omitempty"`
	// BeneficiaryType must be one of BeneficiaryTypeVasp,
	// BeneficiaryTypeSelfHosted or BeneficiaryTypeUnknown. Omitting it is
	// treated as UNKNOWN, which routes to MANUAL.
	BeneficiaryType string `json:"beneficiary_type,omitempty"`
	// OwnershipProofRef is required when BeneficiaryType is SELF_HOSTED and the
	// threshold is exceeded. It is a reference to evidence held by the
	// merchant; the platform does not store the evidence itself.
	OwnershipProofRef string `json:"ownership_proof_ref,omitempty"`
}

// TrThresholdDeclaration is the merchant's threshold assessment. The merchant
// decides, the platform only keeps the record: the platform does not know the
// beneficiary's jurisdiction and should not hold a rule set that drifts from
// the merchant's.
//
// Every field is required once this form is used. The platform also checks that
// DecidedAt is in the past and within the last 24 hours, and that Value and
// FiatAmount are positive.
type TrThresholdDeclaration struct {
	// Exceeded is a pointer so that false and "not supplied" stay
	// distinguishable. This is a compliance field: conflating the two would let
	// a missing value read as "under the threshold".
	Exceeded *bool `json:"exceeded"`
	// Jurisdiction is ISO 3166-1 alpha-2, or EU.
	Jurisdiction string `json:"jurisdiction"`
	// RuleVersion identifies the rule set used. Thresholds get revised, so a
	// jurisdiction alone cannot explain an old assessment.
	RuleVersion string `json:"rule_version"`
	// Value is the threshold amount for that jurisdiction, as a decimal string.
	Value string `json:"value"`
	// Currency prices both Value and FiatAmount.
	Currency string `json:"currency"`
	// FiatAmount is the converted fiat value at assessment time.
	FiatAmount string `json:"fiat_amount"`
	// DecidedAt is a Unix second timestamp. It must be in the past and within
	// the last 24 hours: exchange rates move, so without a point in time the
	// converted amount cannot be reproduced.
	DecidedAt int64 `json:"decided_at"`
}

// TrPostTransferRequest supplies Travel Rule data for a deposit that already
// settled without an incoming authorisation.
//
// Locate the deposit by Txid and Coin (BeneficiaryAddress optional). TrQueryTransfer
// must have run first — this endpoint never starts a lookup of its own, because
// that would put an asynchronous wait inside a data submission. With no reusable
// lookup result the platform answers 615. The CodeVASP reverse-lookup id that
// AssetTransferDataRequest needs is filled by the platform from its task table;
// do not send queryTransfer's request_id back.
type TrPostTransferRequest struct {
	// VaspId is optional, and must match the own VASP that created the lookup
	// when set. Omitted, the platform infers the merchant's single enabled VASP.
	VaspId string `json:"vasp_id,omitempty"`
	// Txid and Coin locate the completed queryTransfer task. They are required.
	Txid string `json:"txid"`
	Coin string `json:"coin"`
	// BeneficiaryAddress is optional. When omitted the platform falls back to
	// the deposit record for this coin and txid, matching TrQueryTransfer.
	BeneficiaryAddress string `json:"beneficiary_address,omitempty"`
	// BeneficiaryCountryCode is the beneficiary's country or region code (ISO
	// 3166-1 alpha-2), at most 10 characters.
	BeneficiaryCountryCode string `json:"beneficiary_country_code,omitempty"`
	Tag                    string `json:"tag,omitempty"`
	Payload                string `json:"payload"`
	// OriginatorPublicKey must be the very same base64 key used to encrypt
	// Payload. Take it from TrQueryTransferData.OriginatorPublicKey. The platform
	// checks it still belongs to the target VASP before sending, which catches a
	// rotated key here rather than as a 422 from the counterparty.
	OriginatorPublicKey string `json:"originator_public_key"`
}

// SetThreshold declares the threshold with full evidence, clearing the boolean
// only form so exactly one of the two is sent.
func (r *TrTransferRequest) SetThreshold(declaration TrThresholdDeclaration) {
	r.Threshold = &declaration
	r.IsExceedingThreshold = nil
}

// SetThresholdExceeded declares only whether the threshold was exceeded,
// clearing any fuller declaration.
//
// Prefer SetThreshold. This form cannot answer which jurisdiction and rule
// version the decision rested on, so the platform records the transfer as having
// incomplete evidence and an audit cannot reconstruct the reasoning from
// platform data alone.
func (r *TrTransferRequest) SetThresholdExceeded(exceeded bool) {
	r.IsExceedingThreshold = &exceeded
	r.Threshold = nil
}

// NewThresholdExceeded returns a pointer suitable for
// TrThresholdDeclaration.Exceeded and
// TrTransferRequest.IsExceedingThreshold.
func NewThresholdExceeded(exceeded bool) *bool {
	return &exceeded
}

// TrReceiveAuditRequest submits the merchant's deposit audit result.
//
// After reviewing the Travel Rule information for an inbound deposit, the
// merchant calls this to inform the platform whether the deposit is accepted or
// rejected.
type TrReceiveAuditRequest struct {
	// WaasOrderId is the WAAS deposit order id, required.
	WaasOrderId string `json:"waas_order_id"`
	// Result is the audit decision: "PASS" or "REJECT".
	Result string `json:"result"`
	// ReasonType is the rejection reason type, required when Result is REJECT.
	ReasonType string `json:"reason_type,omitempty"`
	// ReasonMessage is a human readable rejection reason, optional.
	ReasonMessage string `json:"reason_message,omitempty"`
}

// TrRateRequest queries the exchange rate for a coin in a given jurisdiction.
type TrRateRequest struct {
	// VaspId is the merchant's VASP ID.
	VaspId string `json:"vasp_id"`
	// Coin is the platform coin name (e.g. usdt_trc20).
	Coin string `json:"coin"`
	// CountryCode is the ISO 3166-1 alpha-2 country code.
	CountryCode string `json:"country_code"`
	// FiatCode is the fiat currency code (e.g. SGD, EUR).
	FiatCode string `json:"fiat_code"`
}

// TrHotWalletRequest queries the platform hot wallet address for a coin.
type TrHotWalletRequest struct {
	// Coin is the platform coin name (e.g. usdt_trc20).
	Coin string `json:"coin"`
}
