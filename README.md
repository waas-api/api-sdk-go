# api-sdk-go

## Install
```bash
go get github.com/waas-api/api-sdk-go
```

## Shop Client Example
```go
package example

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/waas-api/api-sdk-go/client"
	"testing"
	"time"
)

var (
	testClient client.Client
)

func init() {
	var conf = client.Config{
		AppId:      "asdfau9imt86qky9",
		Version:    "1.0",
		KeyVersion: "admin",
		BaseUrl:    "http://api.xxx.com/shopapi",
		PrivateKey: `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCY7RWlhM51ArHr
QIuWd1tqABES34/3gqSegp+PW1nu7lL0w9z/+dB3GZP243LO54v2K/QHrDHuEEPc
VD4WhaTtrho55YRkXFKQNCmE3W/pKZYnU+BOEBEF7wZBt3X+82xNafKvHscfNl1m
y2to+P74nLGE6kQNZrA+0RGxib9k9JxV1TsNVxLYSlf4TJ4Ikb82qtXMxEXDaEC7
mFNtoefJJShw+BMwqmRfOhDP8LG4+10/Kx2ZT0lxyHdF/NyWOazzDzcwxT6Hzzzh
sP2yNW9tLdlk+SnMVsZEqOBNKzraYCRBhsis0+zmWejQQ5Q3Nu3CHg088+WLci+9
ee7G3zLzAgMBAAECggEAQCtb5fRwXZEf70NKT30OEtCsWWsOEiHzyb+uDI2ckzHW
BXcaiR7eZtuIxxRx3Hg0truCzqVm3ipdD1saIoE5z7I6twikISjMTE5XDbWNfB1D
MIV1ncwIGKFP0suU68JhM6q9dtZHX8WEM9ov3AB/nPrDUq6ql6T7V6CK+CCA+28z
DG6Bh8jgGMCGyPtvi7ku09pJUGLwRBfRGE2wpcZ4nvSLwbv9Eyaf2ZIyZw6MH6lF
IyI9uVY5ePWh/vVQdbXFmSH2GAuxzxz3T9IvMwUyXiK4t7hVWHJlf9/UQpfbFTXc
4V+/Tmn1gQuLmL4oTs1bRg28AhIsunc9yxlr3wfmAQKBgQDHLm4LG+VUIgGJhxR6
+KmhXJ3S84PdNhEbnNmRJd2ZQlH38YAjndf2FLTH9KoyWw/hfJp3GTHv716W+T1u
qBUhUw7ELugzNY0scxG0xBt+9hJAku+MwgXx53ZnDfV6iRKbc8x/RNRs+OQi8nCa
PO3pdKNrMOHtohuYp0+jDAhiMwKBgQDEjMiBPvw6ZWa2Jm2Q9FhSwUc86ZiT+o3M
AyoQtIFVXWhCM4I5Yk5JzDIi05iJb/dtyulp9UK+/HIKaJtj2Shsp5CZMW9UISea
klrtk/xS0A4qUUOxNxOFNzQl466RULxLCR0kmLqJ6ou8hHpOkdvlGqRbE5JVVOCM
akoa8iysQQKBgBT5QaMv080xK4JE1BZC2vHf48qT093WVKTYtlw/ZX8+6Yy3RGv7
sgL6mTK5A7b7ucdfrJA/+e8vAIHbSum9D0SMD3D/E3pY+D2m/EVRpSeQV8mu70Se
JawcWG5vnNrDVk9COVVpdQjoiHVZnBvRsKe1nYOrCQ9R06AWdh9QJA3bAoGBAIvj
d0Elxvb4/KVfrFOi1MnxbfZYe5O2m/07s1C4Z+SN2opjhqe44+d6QaSv3LzUx9GI
vaAAQ0US/0eRNCdYg4DxseSWXpoODtXgnH7C+K8oDSzpMbiLboU9yQu+hJxATgNJ
tUg6u2k1WccOss4A2fSxhZCc2WWKR1covx12h30BAoGBALZ8IpYY5IJuFXM0aYg5
QbOLlDG0Z13bIpKmgk5IHq53uEkR2+ttSN7i2W3fJhlpUpr4HFXEP5Uk3Q7KE4De
ziVkAkNnZ4c8TISG2SANqaSZggQWXnZNu3am7P/C/19EHOGJigM/wsbjw5KXMqMY
ny5QBi2nWF73omosGLjTrSZ2
-----END PRIVATE KEY-----`,
		PlatformPublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NwyEfQupjAtS7zIeMuR
995t5fzW9FRm9i3+WKQlfLf81wb2dxUyZh2kalCZkkXHbJyyv2XDhMidf1l3kZo/
gCXS+RHmsfinCRE6Y4rkFPLhYvq0tGhkoVDFVhPHZGdRkaUBRWlj8pN/BuyMYLMY
uGrYAQb2J/c4UG0nCB/VuqQ+WsQoNMHxIU/HGehsShHI99maezheP0F6QNIPUtxe
GDKQ52Ks1dWwtIq433MiwRDWaGfRXMVzK+D99BET09e41lJVqvNijhRHwXo6bxjV
kJRYmCGShTkYITeDVhd6NpV/mhPrRSQcwEXjJSObHcbh9UhIZjZGAw56Qfqz66wk
lwIDAQAB
-----END PUBLIC KEY-----`,
	}

	testClient = client.NewClient(conf)
}

func Test_client_CoinList(t *testing.T) {
	params := client.CoinListRequest{
		Coin: "trx",
	}
	// get shop support coins
	res, err := testClient.CoinList(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}
```

> See more example in file `example/client_test.go`.

## Callback Server Example
```go
package example

import (
	"github.com/waas-api/api-sdk-go/callback_server"
	"github.com/waas-api/api-sdk-go/crypto"
	"log"
	"net/http"
	"testing"
	"time"
)

var (
	privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCY7RWlhM51ArHr
QIuWd1tqABES34/3gqSegp+PW1nu7lL0w9z/+dB3GZP243LO54v2K/QHrDHuEEPc
VD4WhaTtrho55YRkXFKQNCmE3W/pKZYnU+BOEBEF7wZBt3X+82xNafKvHscfNl1m
y2to+P74nLGE6kQNZrA+0RGxib9k9JxV1TsNVxLYSlf4TJ4Ikb82qtXMxEXDaEC7
mFNtoefJJShw+BMwqmRfOhDP8LG4+10/Kx2ZT0lxyHdF/NyWOazzDzcwxT6Hzzzh
sP2yNW9tLdlk+SnMVsZEqOBNKzraYCRBhsis0+zmWejQQ5Q3Nu3CHg088+WLci+9
ee7G3zLzAgMBAAECggEAQCtb5fRwXZEf70NKT30OEtCsWWsOEiHzyb+uDI2ckzHW
BXcaiR7eZtuIxxRx3Hg0truCzqVm3ipdD1saIoE5z7I6twikISjMTE5XDbWNfB1D
MIV1ncwIGKFP0suU68JhM6q9dtZHX8WEM9ov3AB/nPrDUq6ql6T7V6CK+CCA+28z
DG6Bh8jgGMCGyPtvi7ku09pJUGLwRBfRGE2wpcZ4nvSLwbv9Eyaf2ZIyZw6MH6lF
IyI9uVY5ePWh/vVQdbXFmSH2GAuxzxz3T9IvMwUyXiK4t7hVWHJlf9/UQpfbFTXc
4V+/Tmn1gQuLmL4oTs1bRg28AhIsunc9yxlr3wfmAQKBgQDHLm4LG+VUIgGJhxR6
+KmhXJ3S84PdNhEbnNmRJd2ZQlH38YAjndf2FLTH9KoyWw/hfJp3GTHv716W+T1u
qBUhUw7ELugzNY0scxG0xBt+9hJAku+MwgXx53ZnDfV6iRKbc8x/RNRs+OQi8nCa
PO3pdKNrMOHtohuYp0+jDAhiMwKBgQDEjMiBPvw6ZWa2Jm2Q9FhSwUc86ZiT+o3M
AyoQtIFVXWhCM4I5Yk5JzDIi05iJb/dtyulp9UK+/HIKaJtj2Shsp5CZMW9UISea
klrtk/xS0A4qUUOxNxOFNzQl466RULxLCR0kmLqJ6ou8hHpOkdvlGqRbE5JVVOCM
akoa8iysQQKBgBT5QaMv080xK4JE1BZC2vHf48qT093WVKTYtlw/ZX8+6Yy3RGv7
sgL6mTK5A7b7ucdfrJA/+e8vAIHbSum9D0SMD3D/E3pY+D2m/EVRpSeQV8mu70Se
JawcWG5vnNrDVk9COVVpdQjoiHVZnBvRsKe1nYOrCQ9R06AWdh9QJA3bAoGBAIvj
d0Elxvb4/KVfrFOi1MnxbfZYe5O2m/07s1C4Z+SN2opjhqe44+d6QaSv3LzUx9GI
vaAAQ0US/0eRNCdYg4DxseSWXpoODtXgnH7C+K8oDSzpMbiLboU9yQu+hJxATgNJ
tUg6u2k1WccOss4A2fSxhZCc2WWKR1covx12h30BAoGBALZ8IpYY5IJuFXM0aYg5
QbOLlDG0Z13bIpKmgk5IHq53uEkR2+ttSN7i2W3fJhlpUpr4HFXEP5Uk3Q7KE4De
ziVkAkNnZ4c8TISG2SANqaSZggQWXnZNu3am7P/C/19EHOGJigM/wsbjw5KXMqMY
ny5QBi2nWF73omosGLjTrSZ2
-----END PRIVATE KEY-----
`

	// provide by platform
	platformPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NwyEfQupjAtS7zIeMuR
995t5fzW9FRm9i3+WKQlfLf81wb2dxUyZh2kalCZkkXHbJyyv2XDhMidf1l3kZo/
gCXS+RHmsfinCRE6Y4rkFPLhYvq0tGhkoVDFVhPHZGdRkaUBRWlj8pN/BuyMYLMY
uGrYAQb2J/c4UG0nCB/VuqQ+WsQoNMHxIU/HGehsShHI99maezheP0F6QNIPUtxe
GDKQ52Ks1dWwtIq433MiwRDWaGfRXMVzK+D99BET09e41lJVqvNijhRHwXo6bxjV
kJRYmCGShTkYITeDVhd6NpV/mhPrRSQcwEXjJSObHcbh9UhIZjZGAw56Qfqz66wk
lwIDAQAB
-----END PUBLIC KEY-----
`
)

func Test_CallbackServer(t *testing.T) {

	http.HandleFunc("/callback/deposit", callback_server.NewHandlerDeposit(func(request callback_server.DepositCallbackRequest) callback_server.DepositCallbackResponse {

		log.Println("get deposit callback", request)

		ret := callback_server.DepositCallbackResponse{}

		// check request sign
		if err := crypto.CallbackServerVerifyRequestSign(request, platformPublicKey); err != nil {
			ret.Status = 500
			log.Println("verify sign fail", err)
			return ret
		}

		// check info according to your needs
		{
			var localAmount = "10.0089"
			if localAmount != request.Data.Amount {
				ret.Status = 500
				ret.Data.SuccessData = "amount invalid"
				return ret
			}
		}

		// return success after all check is OK
		ret.Status = 200
		ret.Data.SuccessData = "success"

		// generate sign for response
		if sign, err := crypto.CallbackServerGenResponseSignOnly(ret.Data, privateKey); err != nil {
			ret.Status = 500
			log.Println("gen sign fail", err)
			return ret
		} else {
			ret.Sign = sign
		}

		return ret
	}))

	log.Println("Starting server at port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
```

> See more example in file `example/server_test.go`.

## Travel Rule (CODE)

The Travel Rule endpoints use the v2 signature scheme: the signature travels in
HTTP headers and the request body is signed exactly as sent. This is a separate
client from `client.NewClient`, which signs by inserting a `sign` field into the
body. Both can be used in the same process.

Only the CODE network is covered. A lookup that finds nothing means the address
is unknown to CODE, not that the transfer is exempt from the Travel Rule.

### Client

```go
trClient, err := client.NewClientV2(client.ConfigV2{
    AppId:             "your-app-id",
    BaseUrl:           "https://api.example.com/shopapi/v2",
    PrivateKey:        merchantRsaPrivateKeyPem, // same RSA key as v1
    PlatformPublicKey: platformRsaPublicKeyPem,  // verifies response signatures
})
```

Five methods: `TrVaspList`, `TrVerifyAddress`, `TrTransfer`, `TrQueryTransfer`,
`TrPostTransfer`.

`coin` is the platform coin name, which already identifies the chain (for example
`usdt_trc20`). Requests do not carry a separate `network` field. For inbound
callbacks, the platform sends `coin` when the provider supplied a network and
the platform resolved one exact match; otherwise it sends all usable candidates
in `possible_coins`. A currency with no usable mapping returns 612.

Check the error before touching `res.Data`. On any non-200 business status the
platform sends no data object, so `Data` is nil and the status arrives as an
`*ApiErrorV2`:

```go
res, err := trClient.TrTransfer(ctx, request)
if err != nil {
    // client.StatusCode(err) gives the business status
    return err
}
// res.Data is non-nil here
```

### The directory is paged

`TrVaspList` takes `vasp_id`, `keyword`, `page` and `page_size`, all optional,
and answers with `items` plus `page`, `page_size` and `total`. `total` counts
everything matching the query, so page until the collected items reach it:

```go
res, err := trClient.TrVaspList(ctx, client.TrVaspListRequest{Keyword: "Upbit"})
if err != nil { /* ... */ }
for _, vasp := range res.Data.Items {
    // vasp.PublicKeys[i].Value is the base64 key
}
```

`page_size` defaults to 50; above 200 the platform answers 613.

`Status` is the platform's local approval state, and only `ACTIVE` entries come
back. Provider service health is not part of the entry: it means something
different, this endpoint reads a local snapshot so the value would be stale, and
"reachable" reads too easily as "cleared to trade". Real availability shows up when
a request is made — `TrTransfer` answers 617 with the provider's `errorType`.

### `Result` is only ever verified or denied

`TrTransfer` answers `ResultVerified` or `ResultDenied`. A `PASS` route reports
verified, and `MANUAL` reports denied with `ReasonLackOfInformation`. So branching
on `Result` alone is correct:

```go
if res.Data.Result != client.ResultVerified {
    return fmt.Errorf("not cleared: %s %s", res.Data.ReasonType, res.Data.ReasonMessage)
}
```

`RouteDecision` explains why, and is only needed to distinguish an actual refusal
by the counterparty from the platform holding the transfer for review. `MANUAL`
reads as denied because those transfers need a human before anything is released.

`ReasonType` is always one of the `Reason*` constants. Platform internal codes and
non-standard provider codes are folded into `ReasonUnknown` with the detail in
`ReasonMessage`, so there is no need to handle unknown values.

### Threshold declaration

Two forms are accepted, and `SetThreshold`/`SetThresholdExceeded` make sure only
one reaches the wire:

```go
request.SetThreshold(client.TrThresholdDeclaration{
    Exceeded: client.NewThresholdExceeded(true), Jurisdiction: "EU",
    RuleVersion: "2026-01", Value: "1000", Currency: "EUR",
    FiatAmount: "1.20", DecidedAt: time.Now().Unix(),
})
```

`SetThresholdExceeded(true)` is accepted too, but a bare boolean cannot answer
which jurisdiction and rule version the decision rested on, so the platform marks
those records as carrying incomplete evidence and an audit cannot reconstruct the
reasoning from platform data alone. Prefer the full form.

`BeneficiaryType` omitted is treated as `UNKNOWN`, which routes to `MANUAL` rather
than releasing.

### Payload encryption

The IVMS101 payload is encrypted end to end. The platform never decrypts it, so
the completeness of the identity data is yours to get right. Required fields vary
by jurisdiction and by the counterparty's `alliance_name`: Europe, Hong Kong and
GTR require `dateOfBirth` for natural persons.

The ciphertext and the public key that produced it must always travel together.
The platform forwards that key to the counterparty as the identifier telling it
which private key to decrypt with, and a NaCl box ciphertext is bound to one key
pair. During a key rotation more than one key is valid at once, so sourcing them
independently is a real failure mode. `ApplyToTransfer` sets both:

```go
encrypted, err := client.EncryptPayload(payload, ownEd25519PrivateKey, beneficiaryPubKey)
if err != nil { /* ... */ }
encrypted.ApplyToTransfer(&request) // sets Payload and BeneficiaryPublicKey together
```

Take `beneficiaryPubKey` from `TrVaspList` and pass it through unchanged: base64
is case sensitive.

### Status 618 is normal, not a fault

VASP lookups (`TrVerifyAddress` without a beneficiary VASP, and
`TrQueryTransfer`) are asynchronous underneath. The platform waits about 8
seconds inside the request, while the provider advises polling no more often than
every 10 seconds, so **the first call almost always returns 618**. Retry the same
call with the same parameters after 10 seconds or more; a background poll fills
in the result. Results are reused for 24 hours, so retrying does not burn quota.

```go
res, err := trClient.TrVerifyAddress(ctx, request)
if client.IsSearchProcessing(err) {
    // no result yet, retry in >= 10s
}
```

The SDK does not retry internally: a blocking wait of 10 seconds or more inside
your request handler is rarely what you want.

`TrPostTransfer` needs a finished lookup, and never starts one itself — that would
put an asynchronous wait inside a data submission. Locate the deposit by `Txid`
and `Coin` (`BeneficiaryAddress` optional). With no reusable result the platform
answers 615.

Encrypt the payload for `OriginatorPublicKey` from the lookup result.

### Callback server

Seven endpoints on your side. Signature verification runs inside each handler and
a failed verification never reaches your business function.

```go
signer, _ := callback_server.NewMemorySigner(ed25519PrivateKeyBase64)
server, _ := callback_server.NewTrServer(callback_server.TrServerConfig{
    PlatformPublicKey: platformRsaPublicKeyPem,
    Signer:            signer,
    NonceStore:        myRedisNonceStore,
    ErrorLog:          func(err error) { log.Println("callback rejected:", err) },
})

mux.Handle(callback_server.TrPathSignature, server.HandleSignature())
mux.Handle(callback_server.TrPathTransfer, server.HandleTransfer(
    func(req callback_server.TrTransferCallbackRequest) callback_server.TrTransferCallbackResponse {
        // your KYC and sanctions logic
    }))
```

Points worth knowing:

- **`NonceStore` needs shared storage.** There is no in-memory default on
  purpose: a process local map silently stops deduplicating as soon as the
  endpoint runs more than one instance. A store outage causes the callback to be
  refused rather than accepted unchecked.
- **Callback responses are not signed.** The platform checks only that the body
  is valid JSON with an allowed `result`. This differs from v1, where the
  response carries a `sign` field.
- **Decrypt with the key the platform supplies** (`originator_public_key`, or
  `beneficiary_public_key` on postTransfer). That is the key it actually verified
  the inbound request against. Never use the public key from a raw inbound
  header: it is attacker supplied, and verifying a signature with it proves
  nothing.
- **Inbound callbacks carry resolved coins or candidate sets.** `verifyAddress`
  supplies candidate main-chain names in `possible_coins`, which must each be
  checked against the decrypted address. `transfer` supplies either one exact
  platform `coin` when the counterparty sent a network, or configured deposit
  coin candidates in `possible_coins` when it did not. A `coin` in a postTransfer
  reply is mapped back before the counterparty sees it. When no usable candidate
  exists, the platform refuses with `NOT_SUPPORTED_SYMBOL` without calling the
  merchant callback.
- **`signature` sits on the critical path.** It is called before every outbound
  CodeVASP request, including each poll of an in-flight lookup. Roughly 100
  concurrent lookups produce about 10 calls per second, with a 3 second timeout.
- **`transferResult` must be idempotent.** It is retried more than once, and the
  same `transfer_id`, `status`, `txid` and `vout` must always produce the same
  answer.
- **`transferResult` only reports inbound on-chain outcomes.** It carries
  `status=confirmed` or `status=canceled`, together with the provider transfer
  identifier and applicable chain fields. Authorisation for your own withdrawal
  is returned synchronously by the platform `transfer` endpoint and is not sent
  through this callback.
- **The reason field is `reason_message` everywhere**, in both directions and on
  every callback. It matters most on responses: the platform reads only that name,
  so a body built by hand under any other one loses the detail with no error, and
  the counterparty receives an empty reason.
- **Health must cover the signer.** Otherwise a broken signer is only discovered
  when a live compliance exchange needs a signature. `HealthCheckSigner` signs a
  probe and verifies it against your registered public key, which also catches a
  signer wired to the wrong key.

### Private key handling

Ed25519 private keys must live in an approved HSM, KMS or key management system,
and must never appear in a config file, log, ticket or chat message. The platform
neither receives nor stores them. Implement `Signer` against your key system;
`NewMemorySigner` is for tests and self managed storage.

One asymmetry to plan around: a **sign-only** HSM or KMS is sufficient for the
`signature` callback, but it **cannot decrypt payloads**. NaCl box needs the raw
private key for scalar multiplication, which is not a signing operation. If the
key must never leave the hardware, payload encryption and decryption have to
happen inside that boundary too, with only ciphertext crossing it.

> See more example in file `example/travel_rule_test.go`.
