package callback_server

import (
	"encoding/json"
	"io"
	"net/http"
)

type WithdrawCallbackRequest struct {
	Sign string                      `json:"sign"`
	Data WithdrawCallbackRequestData `json:"data"`
}

type WithdrawCallbackRequestData struct {
	TradeId string `json:"trade_id"`
	Address string `json:"address"`
	Amount  string `json:"amount"`
	Chain   string `json:"chain"`
	Coin    string `json:"coin"`
	Fee     string `json:"fee"`
	Msg     string `json:"msg"`
	Time    string `json:"time"`
	Total   string `json:"total"`
	Txid    string `json:"txid"`
	Status  int    `json:"status"`
	Type    int    `json:"type"`
}

type WithdrawCallbackResponse struct {
	Status int `json:"status"`
	Data   struct {
		SuccessData string `json:"success_data"`
	} `json:"data"`
	Sign string `json:"sign"`
}

func NewHandlerWithdraw(businessFn func(WithdrawCallbackRequest) WithdrawCallbackResponse) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		request := WithdrawCallbackRequest{}

		// this block can be in web server middleware or your custom controller
		{
			bs, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte(err.Error()))
				return
			}
			err = json.Unmarshal(bs, &request)
		}

		// exec your business code
		response := businessFn(request)

		// this block can be in web server middleware or your custom controller
		{
			resBytes, err := json.Marshal(response)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
				return
			}
			w.WriteHeader(200)
			w.Write(resBytes)
		}
	}
}
