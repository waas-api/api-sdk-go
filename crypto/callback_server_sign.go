package crypto

import (
	"encoding/json"
)

// CallbackServerVerifyRequestSign shop callback server verify the request sign sent by platform.
//
//	@param reqBody, http request body, type can be []byte, string or struct.
//	@param pubKey, rsa public key, provided by platform.
func CallbackServerVerifyRequestSign(reqBody interface{}, pubKey string) error {
	var reqBase struct {
		Sign string          `json:"sign"`
		Data json.RawMessage `json:"data"`
	}
	if bs, ok := reqBody.([]byte); ok {
		if err := json.Unmarshal(bs, &reqBase); err != nil {
			return err
		}
	} else if s, ok := reqBody.(string); ok {
		if err := json.Unmarshal([]byte(s), &reqBase); err != nil {
			return err
		}
	} else {
		bs, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(bs, &reqBase); err != nil {
			return err
		}
	}

	return ApiVerifySign(ParseJsonToClassMap(string(reqBase.Data)), pubKey, reqBase.Sign)
}

// CallbackServerGenResponseSign shop callback server generate sign for the response to the platform notify
//
//	@param resBody the http body response to te platform notify request, type can be []byte, string or struct.
//	@param priKey rsa private key, generated by shop client.
//	@return newResBody new response body with a sign field.
//	 if reqBody type is []byte, return newReqBody type is []byte.
//	 if reqBody type is string, return newReqBody type is string.
//	 if reqBody type is struct, return newReqBody type is map[string]interface{}.
func CallbackServerGenResponseSign(resBody interface{}, priKey string) (resBodyWithSign interface{}, err error) {
	var resBase struct {
		Status int             `json:"status"`
		Sign   string          `json:"sign"`
		Data   json.RawMessage `json:"data"`
	}
	if bs, ok := resBody.([]byte); ok {
		if err := json.Unmarshal(bs, &resBase); err != nil {
			return resBody, err
		}
		err, resBase.Sign = ApiSign(ParseJsonToClassMap(string(resBase.Data)), priKey)
		if err != nil {
			return resBody, err
		}
		if bs, err := json.Marshal(resBase); err != nil {
			return resBody, err
		} else {
			return bs, nil
		}
	} else if s, ok := resBody.(string); ok {
		if err := json.Unmarshal([]byte(s), &resBase); err != nil {
			return resBody, err
		}
		err, resBase.Sign = ApiSign(ParseJsonToClassMap(string(resBase.Data)), priKey)
		if err != nil {
			return resBody, err
		}
		if bs, err := json.Marshal(resBase); err != nil {
			return resBody, err
		} else {
			return string(bs), nil
		}
	} else {
		bs, err := json.Marshal(resBody)
		if err != nil {
			return resBody, err
		}
		if err := json.Unmarshal(bs, &resBase); err != nil {
			return resBody, err
		}
		err, resBase.Sign = ApiSign(ParseJsonToClassMap(string(resBase.Data)), priKey)
		if err != nil {
			return resBody, err
		}
		if bs, err := json.Marshal(resBase); err != nil {
			return resBody, err
		} else {
			resBodyWithSign = new(map[string]interface{})
			if err := json.Unmarshal(bs, &resBodyWithSign); err != nil {
				return resBody, err
			}
			return resBodyWithSign, nil
		}
	}
}

// CallbackServerGenResponseSignOnly shop callback server generate sign string for the response body
//
//	@param resBodyData the response body 'data' field value, the type should be one of struct, struct point or map[string]interface{}, witch can be marshaled safely.
//	@param priKey rsa private key, generated by shop client.
//	@return sign new crypto string
func CallbackServerGenResponseSignOnly(resBodyData interface{}, priKey string) (sign string, err error) {
	bs, err := json.Marshal(resBodyData)
	if err != nil {
		return "", err
	}
	err, sign = ApiSign(ParseJsonToClassMap(string(bs)), priKey)
	if err != nil {
		return "", err
	}
	return sign, nil
}
