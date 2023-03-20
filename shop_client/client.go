package shop_client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/imroc/req/v3"
	"io"
	"time"
	"waas/signature"
)

type Client interface {
	Post(ctx context.Context, urlPath string, request interface{}, responseRcv interface{}) error
	AddressGetBatch(context.Context, AddressGetBatchRequest) (AddressGetBatchResponse, error)
	AddressSyncStatus(context.Context, AddressSyncStatusRequest) (AddressSyncStatusResponse, error)
	AddressSyncBatchStatus(context.Context, AddressSyncBatchStatusRequest) (AddressSyncBatchStatusResponse, error)
	TransferSubmit(context.Context, TransferSubmitRequest) (TransferSubmitResponse, error)
}

func NewClient(config ClientConfig) Client {
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
				// generate signature for request
				bodyReader, err := req.GetBody()
				if err != nil {
					return err
				}
				reqBodyBytes, err := io.ReadAll(bodyReader)
				if err != nil {
					return err
				}
				newReqBodyBytes, err := signature.ShopClientGenPlatformRequestSign(reqBodyBytes, config.PrivateKey)
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

				// verify signature of response
				resBody, err := resp.ToBytes()
				if err != nil {
					resp.Err = fmt.Errorf("read response fail: %v", err)
					return nil
				}
				err = signature.ShopClientVerifyPlatformResponseSign(resBody, config.PlatformPublicKey)
				if err != nil {
					resp.Err = fmt.Errorf("verify response signature fail: %v", err)
					return nil
				}

				return nil
			}),
		conf: config,
	}

	return &c
}

type ClientConfig struct {
	// required, provided by platform
	AppId string `json:"app_id" yaml:"app_id"`
	// required, default: 1.0
	Version string `json:"version" yaml:"version"`
	// required, default: admin
	KeyVersion string `json:"key_version" yaml:"key_version"`
	// required, RSA private key value for generate request signature. Create RSA key pair options，length=2048，format=PKCS#8
	PrivateKey string `json:"private_key" yaml:"private_key"`
	// required, RSA public key value for verify API response，provided by platform
	PlatformPublicKey string `json:"platform_public_key" yaml:"platform_public_key"`
	// required, provided by platform
	BaseUrl string `json:"base_url" yaml:"base_url"`
}

func (rcv ClientConfig) newBaseRequest() baseRequest {
	return baseRequest{
		AppId:      rcv.AppId,
		Version:    rcv.Version,
		KeyVersion: rcv.KeyVersion,
		Time:       fmt.Sprintf("%d", time.Now().Unix()),
	}
}

type client struct {
	*req.Client
	conf ClientConfig
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

func (c client) AddressSyncBatchStatus(ctx context.Context, request AddressSyncBatchStatusRequest) (res AddressSyncBatchStatusResponse, err error) {
	reqBody := struct {
		baseRequest
		AddressSyncBatchStatusRequest
	}{
		baseRequest:                   c.conf.newBaseRequest(),
		AddressSyncBatchStatusRequest: request,
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(&res).
		Post(pathAddressSyncBatchStatus.Build(c.conf.BaseUrl))

	return res, err
}

func (c client) TransferSubmit(ctx context.Context, request TransferSubmitRequest) (res TransferSubmitResponse, err error) {
	reqBody := struct {
		baseRequest
		TransferSubmitRequest
	}{
		baseRequest:           c.conf.newBaseRequest(),
		TransferSubmitRequest: request,
	}
	_, err = c.R().SetContext(ctx).
		SetBodyJsonMarshal(reqBody).
		SetSuccessResult(&res).
		Post(pathTransferSubmit.Build(c.conf.BaseUrl))

	return res, err
}
