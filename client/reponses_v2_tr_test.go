package client

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The platform's failure helper passes an empty slice as the data value, so
// every business error arrives as "data":[]. Decoding that into a struct pointer
// fails, which would swallow the status and turn a normal 618 into an opaque
// decode error.
func TestBusinessErrorEmptyArrayDataDecodes(t *testing.T) {
	const body = `{"status":618,"msg":"反查处理中","data":[],"date_time":"2026-07-29 12:00:00","time_stamp":1785297600}`

	var queryTransfer TrQueryTransferResponse
	if err := json.Unmarshal([]byte(body), &queryTransfer); err != nil {
		t.Fatalf("queryTransfer: %v", err)
	}
	if queryTransfer.Status != StatusSearchProcessing {
		t.Errorf("status = %d, want %d", queryTransfer.Status, StatusSearchProcessing)
	}
	if queryTransfer.Msg == "" {
		t.Error("msg was lost")
	}
	if queryTransfer.Data != nil {
		t.Error("Data must stay nil when the platform sent no data object")
	}

	var verifyAddress TrVerifyAddressResponse
	if err := json.Unmarshal([]byte(body), &verifyAddress); err != nil {
		t.Fatalf("verifyAddress: %v", err)
	}
	var transfer TrTransferResponse
	if err := json.Unmarshal([]byte(body), &transfer); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	var postTransfer TrPostTransferResponse
	if err := json.Unmarshal([]byte(body), &postTransfer); err != nil {
		t.Fatalf("postTransfer: %v", err)
	}
	var vaspList TrVaspListResponse
	if err := json.Unmarshal([]byte(body), &vaspList); err != nil {
		t.Fatalf("vaspList: %v", err)
	}
	if vaspList.Data != nil {
		t.Errorf("vaspList data = %+v, want nil", vaspList.Data)
	}
}

func TestAbsentDataVariantsDecode(t *testing.T) {
	bodies := map[string]string{
		"omitted":     `{"status":200,"msg":"ok"}`,
		"null":        `{"status":200,"msg":"ok","data":null}`,
		"empty array": `{"status":613,"msg":"bad param","data":[]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			var res TrTransferResponse
			if err := json.Unmarshal([]byte(body), &res); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if res.Data != nil {
				t.Error("Data must be nil when there is no data object")
			}
			if res.Status == 0 {
				t.Error("status was lost")
			}
		})
	}
}

// encoding/json leaves an absent field untouched, so decoding into a value that
// already holds data would otherwise keep the previous message's data and report
// it alongside the new status.
func TestReusedResponseValueDoesNotKeepStaleData(t *testing.T) {
	var res TrTransferResponse
	if err := json.Unmarshal([]byte(`{"status":200,"data":{"transfer_id":"first"}}`), &res); err != nil {
		t.Fatalf("first decode: %v", err)
	}
	if res.Data == nil {
		t.Fatal("first decode produced no data")
	}
	if err := json.Unmarshal([]byte(`{"status":618,"msg":"processing","data":[]}`), &res); err != nil {
		t.Fatalf("second decode: %v", err)
	}
	if res.Data != nil {
		t.Errorf("stale data survived: %+v", res.Data)
	}
	if res.Status != StatusSearchProcessing {
		t.Errorf("status = %d, want %d", res.Status, StatusSearchProcessing)
	}

	var directory TrVaspListResponse
	if err := json.Unmarshal([]byte(`{"status":200,"data":{"items":[{"vasp_id":"a"}],"total":1}}`), &directory); err != nil {
		t.Fatalf("first directory decode: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"status":200,"data":{"items":[{"vasp_id":"b"}],"total":1}}`), &directory); err != nil {
		t.Fatalf("second directory decode: %v", err)
	}
	if len(directory.Data.Items) != 1 || directory.Data.Items[0].VaspId != "b" {
		t.Errorf("directory accumulated entries: %+v", directory.Data)
	}
	if err := json.Unmarshal([]byte(`{"status":613,"msg":"bad param","data":[]}`), &directory); err != nil {
		t.Fatalf("third directory decode: %v", err)
	}
	if directory.Data != nil {
		t.Errorf("stale directory survived a business error: %+v", directory.Data)
	}
}

// A data field that is not an object is treated as absent, so the caller sees the
// business status rather than a raw decode error. The platform only ever sends an
// object or an empty array, so this only matters as a guard.
func TestNonObjectDataTreatedAsAbsent(t *testing.T) {
	for _, body := range []string{
		`{"status":613,"msg":"bad param","data":"oops"}`,
		`{"status":613,"msg":"bad param","data":0}`,
		`{"status":613,"msg":"bad param","data":false}`,
	} {
		var res TrTransferResponse
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			t.Errorf("body %s returned a decode error: %v", body, err)
			continue
		}
		if res.Data != nil {
			t.Errorf("body %s produced data: %+v", body, res.Data)
		}
		if res.Status != StatusInvalidParameter {
			t.Errorf("body %s lost the status: %d", body, res.Status)
		}
	}
}

func TestMalformedJsonIsAnError(t *testing.T) {
	var res TrTransferResponse
	if err := json.Unmarshal([]byte(`{"status":200,`), &res); err == nil {
		t.Error("malformed JSON was accepted")
	}
}

// Unknown fields in the envelope must be ignored, so the platform can add fields
// without breaking existing clients.
func TestUnknownEnvelopeFieldsIgnored(t *testing.T) {
	var res TrTransferResponse
	body := `{"status":200,"msg":"ok","future_field":{"x":1},"data":{"transfer_id":"t-1"},"another":[1,2]}`
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Data == nil || res.Data.TransferId != "t-1" {
		t.Errorf("data lost alongside unknown fields: %+v", res.Data)
	}
}

// A populated data object must still decode, and the envelope must survive
// alongside it.
func TestPopulatedDataDecodes(t *testing.T) {
	const body = `{"status":200,"msg":"请求成功","data":{"transfer_id":"t-1","route_decision":"TR_CODE","result":"verified","payload":"Y2lwaGVy"},"time_stamp":1785297600}`
	var res TrTransferResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Status != StatusOk || res.TimeStamp != 1785297600 {
		t.Errorf("envelope not decoded: %+v", res.ResponseV2)
	}
	if res.Data == nil {
		t.Fatal("Data is nil for a populated data object")
	}
	if res.Data.TransferId != "t-1" || res.Data.RouteDecision != RouteDecisionTrCode || res.Data.Result != ResultVerified {
		t.Errorf("data not decoded: %+v", res.Data)
	}
	if res.Data.Payload != "Y2lwaGVy" {
		t.Errorf("payload = %q", res.Data.Payload)
	}
}

// Merchant requests carry no network field at all: the platform coin name
// already identifies the chain, and the platform resolves the network from its
// own coin mapping.
//
// The field is checked by name on the type rather than in marshalled output,
// because an omitempty field would be absent from the JSON whenever it happened
// to be empty and the check would pass regardless.
func TestRequestTypesHaveNoNetworkField(t *testing.T) {
	types := map[string]reflect.Type{
		"verifyAddress": reflect.TypeOf(TrVerifyAddressRequest{}),
		"transfer":      reflect.TypeOf(TrTransferRequest{}),
		"queryTransfer": reflect.TypeOf(TrQueryTransferRequest{}),
		"postTransfer":  reflect.TypeOf(TrPostTransferRequest{}),
	}
	for name, requestType := range types {
		for i := 0; i < requestType.NumField(); i++ {
			field := requestType.Field(i)
			if strings.HasPrefix(field.Tag.Get("json"), "network") {
				t.Errorf("%s declares a network field (%s); merchant requests must not carry one", name, field.Name)
			}
		}
	}
}

// postTransfer locates the prior queryTransfer by txid+coin; request_id is a
// merchant-side noise path the platform no longer accepts.
func TestPostTransferRequestHasNoRequestId(t *testing.T) {
	requestType := reflect.TypeOf(TrPostTransferRequest{})
	for i := 0; i < requestType.NumField(); i++ {
		field := requestType.Field(i)
		if strings.HasPrefix(field.Tag.Get("json"), "request_id") {
			t.Errorf("postTransfer still declares request_id (%s); locate by txid and coin instead", field.Name)
		}
	}
}

func TestQueryTransferResponseMatchesPlatformContract(t *testing.T) {
	responseType := reflect.TypeOf(TrQueryTransferData{})
	removedFields := map[string]bool{
		"request_id":             true,
		"originator_public_keys": true,
	}
	for i := 0; i < responseType.NumField(); i++ {
		jsonName := strings.Split(responseType.Field(i).Tag.Get("json"), ",")[0]
		if removedFields[jsonName] {
			t.Errorf("queryTransfer response still declares removed field %s", jsonName)
		}
	}
}

func TestVaspListDecodesPagedDirectory(t *testing.T) {
	const body = `{"status":200,"msg":"ok","data":{"items":[{"vasp_id":"code:them","name":"Them","legal_name":"Them Ltd","country_code":"KR","status":"ACTIVE","provider":"code","provider_vasp_id":"them","alliance_name":"code","public_keys":[{"value":"Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=","expires_at":"2027-07-24T06:00:00Z"}]}],"page":2,"page_size":50,"total":51}}`
	var res TrVaspListResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Data == nil {
		t.Fatal("Data is nil for a populated page")
	}
	if res.Data.Page != 2 || res.Data.PageSize != 50 || res.Data.Total != 51 {
		t.Errorf("paging envelope not decoded: %+v", res.Data)
	}
	if len(res.Data.Items) != 1 {
		t.Fatalf("items length = %d, want 1", len(res.Data.Items))
	}
	entry := res.Data.Items[0]
	if entry.VaspId != "code:them" || entry.AllianceName != "code" {
		t.Errorf("entry not decoded: %+v", entry)
	}
	if entry.CountryCode != "KR" || entry.Status != "ACTIVE" || entry.Provider != "code" || entry.ProviderVaspId != "them" {
		t.Errorf("directory metadata not decoded: %+v", entry)
	}
	if len(entry.PublicKeys) != 1 || entry.PublicKeys[0].Value == "" || entry.PublicKeys[0].ExpiresAt == "" {
		t.Errorf("public keys not decoded: %+v", entry.PublicKeys)
	}
}

// An empty page is a legitimate answer, distinct from a business error, so Data
// must still be non-nil.
func TestVaspListEmptyPageIsData(t *testing.T) {
	var res TrVaspListResponse
	if err := json.Unmarshal([]byte(`{"status":200,"msg":"ok","data":{"items":[],"page":1,"page_size":50,"total":0}}`), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Data == nil {
		t.Fatal("an empty page must still decode as data")
	}
	if len(res.Data.Items) != 0 || res.Data.Total != 0 {
		t.Errorf("unexpected content: %+v", res.Data)
	}
}

// The public key is case sensitive and must survive decoding unchanged, since it
// has to be echoed back byte for byte with any ciphertext it encrypted.
func TestVaspKeyCasePreserved(t *testing.T) {
	const key = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="
	var res TrVaspListResponse
	if err := json.Unmarshal([]byte(`{"status":200,"data":{"items":[{"vasp_id":"code:them","public_keys":[{"value":"`+key+`"}]}]}}`), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := res.Data.Items[0].PublicKeys[0].Value; got != key {
		t.Errorf("public key altered:\n got %q\nwant %q", got, key)
	}
}

// The transfer result enum must stay inside verified/denied on every route. A
// lowercased route decision leaking through here would make a merchant branching
// on ResultVerified read a PASS as a failure.
func TestTransferResultEnumStaysWithinTwoValues(t *testing.T) {
	cases := map[string]struct{ decision, result string }{
		"tr_code": {RouteDecisionTrCode, ResultVerified},
		"pass":    {RouteDecisionPass, ResultVerified},
		"manual":  {RouteDecisionManual, ResultDenied},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			body := `{"status":200,"data":{"transfer_id":"t-1","route_decision":"` + want.decision + `","result":"` + want.result + `","reason_message":"detail"}}`
			var res TrTransferResponse
			if err := json.Unmarshal([]byte(body), &res); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if res.Data.Result != ResultVerified && res.Data.Result != ResultDenied {
				t.Errorf("result %q is outside the documented enum", res.Data.Result)
			}
			if res.Data.RouteDecision != want.decision {
				t.Errorf("route decision = %q, want %q", res.Data.RouteDecision, want.decision)
			}
			if res.Data.ReasonMessage != "detail" {
				t.Errorf("reason_message not decoded: %q", res.Data.ReasonMessage)
			}
		})
	}
}

// beneficiary_vasp is passed through unparsed, and is usually null.
func TestTransferBeneficiaryVaspPassedThrough(t *testing.T) {
	const raw = `{"name":"Them Ltd","country":"KR"}`
	var res TrTransferResponse
	if err := json.Unmarshal([]byte(`{"status":200,"data":{"transfer_id":"t-1","beneficiary_vasp":`+raw+`}}`), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(res.Data.BeneficiaryVasp) != raw {
		t.Errorf("beneficiary_vasp altered:\n got %s\nwant %s", res.Data.BeneficiaryVasp, raw)
	}

	var absent TrTransferResponse
	if err := json.Unmarshal([]byte(`{"status":200,"data":{"transfer_id":"t-1","beneficiary_vasp":null}}`), &absent); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if len(absent.Data.BeneficiaryVasp) != 0 && string(absent.Data.BeneficiaryVasp) != "null" {
		t.Errorf("unexpected beneficiary_vasp: %s", absent.Data.BeneficiaryVasp)
	}
}

// coin and contract in the postTransfer result are the platform names, so a
// merchant can look them up in its own coin table.
func TestPostTransferDecodesFullResult(t *testing.T) {
	const body = `{"status":200,"data":{"transfer_id":"local-uuid-1","result":"normal","reason_type":"","reason_message":"","originator_vasp_id":"code:them","coin":"usdt_trc20","contract":"TRON","amount":"1.2","trade_price":"1.00","trade_currency":"USD","is_exceeding_threshold":true,"payload":"Y2lwaGVy"}}`
	var res TrPostTransferResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data := res.Data
	if data == nil {
		t.Fatal("Data is nil")
	}
	if data.TransferId != "local-uuid-1" || data.Result != ResultNormal {
		t.Errorf("envelope fields not decoded: %+v", data)
	}
	if data.OriginatorVaspId != "code:them" || data.Coin != "usdt_trc20" || data.Contract != "TRON" {
		t.Errorf("platform coin fields not decoded: %+v", data)
	}
	if data.Amount != "1.2" || data.TradePrice != "1.00" || data.TradeCurrency != "USD" {
		t.Errorf("amounts not decoded: %+v", data)
	}
	if !data.IsExceedingThreshold {
		t.Error("is_exceeding_threshold must decode as a boolean")
	}
}

// queryTransfer returns the key to encrypt the postTransfer payload for.
func TestQueryTransferDecodesOriginatorPublicKey(t *testing.T) {
	const body = `{"status":200,"data":{"originator_vasp_id":"code:them","result":"valid","reason_type":"","reason_message":"","originator_public_key":"KeyA"}}`
	var res TrQueryTransferResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Data.OriginatorVaspId != "code:them" {
		t.Errorf("originator_vasp_id not decoded: %+v", res.Data)
	}
	if res.Data.OriginatorPublicKey != "KeyA" {
		t.Errorf("originator_public_key = %q", res.Data.OriginatorPublicKey)
	}
}

func TestEncryptedRequestPublicKeyFieldsMatchPlatformContract(t *testing.T) {
	tests := []struct {
		name      string
		request   any
		wantField string
	}{
		{"verifyAddress", TrVerifyAddressRequest{BeneficiaryPublicKey: "key"}, "beneficiary_public_key"},
		{"transfer", TrTransferRequest{BeneficiaryPublicKey: "key"}, "beneficiary_public_key"},
		{"postTransfer", TrPostTransferRequest{OriginatorPublicKey: "key"}, "originator_public_key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.request)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if _, ok := fields[test.wantField]; !ok {
				t.Fatalf("request = %s, missing %s", body, test.wantField)
			}
			if _, ok := fields["beneficiary_pubkey"]; ok {
				t.Fatalf("request still contains removed beneficiary_pubkey: %s", body)
			}
		})
	}
}

// Only one threshold form may reach the wire: sending both would leave the
// platform to pick, and sending the boolean alongside a full declaration
// misrepresents what evidence was recorded.
func TestThresholdSettersAreMutuallyExclusive(t *testing.T) {
	request := TrTransferRequest{Coin: "usdt_trc20"}

	request.SetThresholdExceeded(false)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"is_exceeding_threshold":false`) {
		t.Errorf("boolean declaration missing: %s", body)
	}
	if strings.Contains(string(body), `"threshold"`) {
		t.Errorf("threshold object sent alongside the boolean: %s", body)
	}

	request.SetThreshold(TrThresholdDeclaration{
		Exceeded: NewThresholdExceeded(true), Jurisdiction: "EU", RuleVersion: "2026-01",
		Value: "1000", Currency: "EUR", FiatAmount: "1.20", DecidedAt: 1785297600,
	})
	body, err = json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"threshold":{`) {
		t.Errorf("threshold object missing: %s", body)
	}
	if strings.Contains(string(body), `"is_exceeding_threshold"`) {
		t.Errorf("boolean sent alongside the threshold object: %s", body)
	}

	// Neither form set means neither field on the wire, so the platform reports
	// the missing declaration rather than receiving a false it never decided.
	empty, err := json.Marshal(TrTransferRequest{Coin: "usdt_trc20"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(empty), "threshold") {
		t.Errorf("undeclared threshold reached the wire: %s", empty)
	}
}
