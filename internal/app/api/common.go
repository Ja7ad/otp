package api

import (
	"encoding/json"
	"net/http"

	"github.com/valyala/fasthttp"
)

const (
	_appName     = "otp-api"
	_description = "otp-api is a high-performance, minimalistic API server for generating and validating " +
		"OTP codes (TOTP, HOTP, and OCRA) using the Ja7ad/otp Go library. It offers RESTful endpoints for secure " +
		"authentication workflows, QR code URL generation, and dynamic OCRA suite handling."
	docPath = "/docs"
)

func (e errResp) Error() string {
	return e.Message
}

func writeError(ctx *fasthttp.RequestCtx, statusCode int, msg string, details map[string]any) {
	resp := errResp{
		Code:    http.StatusText(statusCode),
		Message: msg,
		Details: details,
	}
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	_ = json.NewEncoder(ctx).Encode(resp)
}
