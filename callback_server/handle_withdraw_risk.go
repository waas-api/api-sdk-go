package callback_server

import (
	"encoding/json"
	"io"
	"net/http"
)

type WithdrawRiskCallbackRequest struct {
	Sign string                          `json:"sign"`
	Data WithdrawRiskCallbackRequestData `json:"data"`
}

type WithdrawRiskCallbackRequestData struct {
	Amount     string `json:"amount"`
	CoinSymbol string `json:"coin_symbol"`
	Address    string `json:"address"`
	UserId     string `json:"user_id"`
	OrderId    string `json:"order_id"`
	Timestamp  string `json:"timestamp"`
}

type WithdrawRiskCallbackResponse struct {
	Status int    `json:"status"`
	Sign   string `json:"sign"`
	Data   struct {
		StatusCode int    `json:"status_code"`
		Timestamp  int64  `json:"timestamp"`
		OrderId    string `json:"order_id"`
	} `json:"data"`
}

func NewHandlerWithdrawRisk(businessFn func(WithdrawRiskCallbackRequest) WithdrawRiskCallbackResponse) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		request := WithdrawRiskCallbackRequest{}

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
