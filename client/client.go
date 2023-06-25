package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/waas-api/api-sdk/crypto"
	"io"
	"time"
)

type Client interface {
	Post(ctx context.Context, urlPath string, request interface{}, responseRcv interface{}) error

	// CoinList Coin related api for the merchant
	CoinList(context.Context, CoinListRequest) (CoinListResponse, error)

	// AddressGetBatch Return the new address to the merchant
	// The number of addresses obtained at a time is N (default 200), and merchants can request multiple times according to actual needs.
	// For accounts like EOS + memo mode, this interface only returns memo, with the interface: /address/coinAccount
	// Note: Platform eth, bnb_bsc (bsc main chain), ht_heco (heco main chain) are sharing the eth address, when requesting the address-related api please use eth as the parameter value of coin (coin=eth )
	AddressGetBatch(context.Context, AddressGetBatchRequest) (AddressGetBatchResponse, error)

	// AddressSyncStatus After the merchant assigns the address to the user, it must notify the platform to update the address usage status through the "Status Synchronization Interface".
	AddressSyncStatus(context.Context, AddressSyncStatusRequest) (AddressSyncStatusResponse, error)

	// AddressList Query address usage status, address ownership.
	AddressList(context.Context, AddressListRequest) (AddressListResponse, error)

	// Transfer The merchant initial a on-chain withdrawal request will use this API. In order to complete the withdrawl request, merchant need to prepare the callback API for risk control callback. ( Detail please refer to the Risk Control callback -> The second review of the withdrawal order)
	Transfer(context.Context, TransferRequest) (TransferResponse, error)
}

func NewClient(config Config) Client {
	if config.AppId == "" {
		panic("app_id required")
	}
	if config.PrivateKey == "" {
		panic("private_key required")
	}
	if config.PlatformPublicKey == "" {
		panic("remote_public_key required")
	}
	if config.BaseUrl == "" {
		panic("base_url required")
	}

	c := client{
		Client: req.C().
			SetBaseURL(config.BaseUrl).
			EnableDumpEachRequest().
			OnBeforeRequest(func(client *req.Client, req *req.Request) error {
				// generate crypto for request
				bodyReader, err := req.GetBody()
				if err != nil {
					return err
				}
				reqBodyBytes, err := io.ReadAll(bodyReader)
				if err != nil {
					return err
				}
				newReqBodyBytes, err := crypto.ShopClientGenPlatformRequestSign(reqBodyBytes, config.PrivateKey)
				if err != nil {
					return err
				}
				req.SetBodyJsonBytes(newReqBodyBytes.([]byte))
				return nil
			}).
			OnAfterResponse(func(client *req.Client, resp *req.Response) error {
				if resp.Err != nil { // There is an underlying error, e.g. network error or unmarshal error.
					return nil
				}
				if !resp.IsSuccessState() {
					// Neither a success response nor an error response, record details to help troubleshooting
					resp.Err = fmt.Errorf("bad status: %s\nraw content:\n%s", resp.Status, resp.Dump())
					return nil
				}

				// api error
				if errType, ok := resp.SuccessResult().(interface{ ApiError() error }); ok && errType.ApiError() != nil {
					resp.Err = errType.ApiError() // Convert api error into go error
					return nil
				}

				// verify crypto of response
				resBody, err := resp.ToBytes()
				if err != nil {
					resp.Err = fmt.Errorf("read response fail: %v", err)
					return nil
				}
				err = crypto.ShopClientVerifyPlatformResponseSign(resBody, config.PlatformPublicKey)
				if err != nil {
					resp.Err = fmt.Errorf("verify response crypto fail: %v", err)
					return nil
				}

				return nil
			}),
		conf: config,
	}

	return &c
}

type Config struct {
	// required, provided by platform
	AppId string `json:"app_id" yaml:"app_id"`
	// required, default: 1.0
	Version string `json:"version" yaml:"version"`
	// required, default: admin
	KeyVersion string `json:"key_version" yaml:"key_version"`
	// required, RSA private key value for generate request crypto. Create RSA key pair options，length=2048，format=PKCS#8
	PrivateKey string `json:"private_key" yaml:"private_key"`
	// required, RSA public key value for verify API response，provided by platform
	PlatformPublicKey string `json:"platform_public_key" yaml:"platform_public_key"`
	// required, provided by platform
	BaseUrl string `json:"base_url" yaml:"base_url"`
}

func (rcv Config) newBaseRequest() baseRequest {
	return baseRequest{
		AppId:      rcv.AppId,
		Version:    rcv.Version,
		KeyVersion: rcv.KeyVersion,
		Time:       fmt.Sprintf("%d", time.Now().Unix()),
	}
}

type client struct {
	*req.Client
	conf Config
}

func (c client) Post(ctx context.Context, urlPath string, request interface{}, responseRcv interface{}) (err error) {
	reqBody := make(map[string]interface{})
	bs, err := json.Marshal(request)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bs, &reqBody)
	if err != nil {
		return err
	}
	for k, v := range c.conf.newBaseRequest().Mapping() {
		reqBody[k] = v
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(responseRcv).
		Post(path(urlPath).Build(c.conf.BaseUrl))

	return err
}

func (c client) CoinList(ctx context.Context, request CoinListRequest) (res CoinListResponse, err error) {
	reqBody := struct {
		baseRequest
		CoinListRequest
	}{
		baseRequest:     c.conf.newBaseRequest(),
		CoinListRequest: request,
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(&res).
		Post(string(pathCoinList))

	return res, err
}

func (c client) AddressGetBatch(ctx context.Context, request AddressGetBatchRequest) (res AddressGetBatchResponse, err error) {
	reqBody := struct {
		baseRequest
		AddressGetBatchRequest
	}{
		baseRequest:            c.conf.newBaseRequest(),
		AddressGetBatchRequest: request,
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(&res).
		Post(pathAddressGetBatch.Build(c.conf.BaseUrl))

	return res, err
}

func (c client) AddressSyncStatus(ctx context.Context, request AddressSyncStatusRequest) (res AddressSyncStatusResponse, err error) {
	reqBody := struct {
		baseRequest
		AddressSyncStatusRequest
	}{
		baseRequest:              c.conf.newBaseRequest(),
		AddressSyncStatusRequest: request,
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(&res).
		Post(pathAddressSyncStatus.Build(c.conf.BaseUrl))

	return res, err
}

func (c client) AddressList(ctx context.Context, request AddressListRequest) (res AddressListResponse, err error) {
	reqBody := struct {
		baseRequest
		AddressListRequest
	}{
		baseRequest:        c.conf.newBaseRequest(),
		AddressListRequest: request,
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(&res).
		Post(pathAddressList.Build(c.conf.BaseUrl))

	return res, err
}

func (c client) Transfer(ctx context.Context, request TransferRequest) (res TransferResponse, err error) {
	reqBody := struct {
		baseRequest
		TransferRequest
	}{
		baseRequest:     c.conf.newBaseRequest(),
		TransferRequest: request,
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(&res).
		Post(pathTransfer.Build(c.conf.BaseUrl))

	return res, err
}
