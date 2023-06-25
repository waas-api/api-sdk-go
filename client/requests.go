package client

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
	pathCoinList          path = "/coin/list"
	pathAddressGetBatch   path = "/address/getBatch"
	pathAddressSyncStatus path = "/address/syncStatus"
	pathAddressList       path = "/address/list"
	pathTransfer          path = "/transfer"
)

type baseRequest struct {
	// Merchant ID assigned by the system when docking
	AppId string `json:"app_id"`
	// interface version number - fixed according to the agreement at the time of access
	Version string `json:"version"`
	// 	key version number: admin / read / arbitrary - can be authorized for any 1-n interfaces
	KeyVersion string `json:"key_version"`
	// timestamp - ignoring timezone timestamp in seconds
	Time string `json:"time"` // unix second of current time
	// RSA-2048 bit key mode
	Sign string `json:"sign"`
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

type CoinListRequest struct {
	// coin name (eg: eth)
	Coin string `json:"coin,omitempty"`
	// Main chain name (query main chain and its tokens, such as: eth)
	Chain string `json:"chain,omitempty"`
	// 1<= N <=Max, N>Max ? N=Max ; N<1 ? N=1
	Page int `json:"page,omitempty"`
	// number of pages per page (20 ~ 500), default 20
	PageSize int `json:"page_size,omitempty"`
}

type AddressGetBatchRequest struct {
	// main chain coin name within 12 characters, the coin name platform shall prevail (if bnb_bsc please use eth)
	Coin string `json:"coin,omitempty"`
}

type AddressSyncStatusRequest struct {
	// address, within 128 characters
	Address string `json:"address,omitempty"`
	// Within 12 characters, the main chain currency of the address (if bnb_bsc, please pass eth)
	Coin string `json:"coin,omitempty"`
	// string within 40, user UID assigned by address
	UserId string `json:"user_id,omitempty"`
}

type AddressListRequest struct {
	// address
	Address string `json:"address,omitempty"`
	// main chain coin name - see the description of the public information of supported coins (if bnb_bsc please use eth)
	Coin string `json:"coin,omitempty"`
	// 1<= N <=Max, if it exceeds Max, take Max, if it is less than 1, return 1
	Page int `json:"page,omitempty"`
	// 1=used, 2=not used
	IsUsed int `json:"is_used,omitempty"`
}

type TransferRequest struct {
	// user ID, out of range error
	UserId string `json:"user_id,omitempty"`
	// currency abbreviation - platform agreement shall prevail
	Coin string `json:"coin,omitempty"`
	// withdrawal amount, an error will occur if it exceeds the range
	Amount string `json:"amount,omitempty"`
	// payment address, an error will occur if it exceeds the range
	Address string `json:"address,omitempty"`
	// memo/tag needs to be filled in when the current currency is eos and its tokens
	Memo string `json:"memo,omitempty"`
	// The unique ID of the merchant's transaction (recommended format: year, month, day, hour, minute, second + 6-digit random number case: 20200311202903000001)
	TradeId string `json:"trade_id,omitempty"`
}
