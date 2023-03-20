package shop_client

import (
	"fmt"
	"strings"
)

type path string

func (p path) Build(baseUrl string) string {
	if strings.HasSuffix(baseUrl, "/") && strings.HasPrefix(string(p), "/") {
		return fmt.Sprintf("%s%s", strings.TrimSuffix(baseUrl, "/"), p)
	}
	if !strings.HasSuffix(baseUrl, "/") && !strings.HasPrefix(string(p), "/") {
		return fmt.Sprintf("%s/%s", baseUrl, p)
	}
	return fmt.Sprintf("%s%s", baseUrl, p)
}

const (
	pathAddressGetBatch        path = "/address/getBatch"
	pathAddressSyncStatus      path = "/address/syncStatus"
	pathAddressSyncBatchStatus path = "/address/syncBatchStatus"
	pathTransferSubmit         path = "/transfer"
)

type baseRequest struct {
	AppId      string `json:"app_id"`
	Version    string `json:"version"`
	KeyVersion string `json:"key_version"`
	Time       string `json:"time"` // unix second of current time
	Sign       string `json:"sign"`
}

func (rcv baseRequest) Mapping() map[string]string {
	ret := make(map[string]string)
	ret["app_id"] = rcv.AppId
	ret["version"] = rcv.Version
	ret["key_version"] = rcv.KeyVersion
	ret["time"] = rcv.Time
	if rcv.Sign != "" {
		ret["sign"] = rcv.Sign
	}
	return ret
}

type AddressGetBatchRequest struct {
	Coin string `json:"coin,omitempty"`
}

type AddressSyncStatusRequest struct {
	Address string `json:"address,omitempty"`
	Coin    string `json:"coin,omitempty"`
	UserId  string `json:"user_id,omitempty"`
}

type AddressSyncBatchStatusRequest struct {
	AddressList []AddressSyncStatusRequest `json:"address_list"`
}

type TransferSubmitRequest struct {
	UserId  string `json:"user_id,omitempty"`
	Coin    string `json:"coin,omitempty"`
	Amount  string `json:"amount,omitempty"`
	Address string `json:"address,omitempty"`
	Memo    string `json:"memo,omitempty"`
	TradeId string `json:"trade_id,omitempty"`
	ShopId  int    `json:"shop_id,omitempty"`
}
