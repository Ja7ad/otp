package api

import (
	"strings"

	_ "github.com/ja7ad/otp/internal/app/docs"
	fastHttpSwagger "github.com/swaggo/fasthttp-swagger"
	"github.com/valyala/fasthttp"
)

func routers(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	if path == "/docs" {
		ctx.Redirect("/docs/index.html", fasthttp.StatusFound)
		return
	}

	if strings.HasPrefix(path, "/docs/") {
		ctx.SetUserValue("filepath", strings.TrimPrefix(path, "/docs"))
		fastHttpSwagger.WrapHandler()(ctx)
		return
	}

	switch path {
	case "/totp/generate":
		totpGeneration()(ctx)
	case "/totp/validate":
		totpValidation()(ctx)
	case "/hotp/generate":
		hotpGeneration()(ctx)
	case "/hotp/validate":
		hotpValidation()(ctx)
	case "/ocra/generate":
		ocraGeneration()(ctx)
	case "/ocra/validate":
		ocraValidation()(ctx)
	case "/ocra/suites":
		listOCRASuites()(ctx)
	case "/ocra/suite":
		ocraSuiteConfig()(ctx)
	case "/otp/url":
		otpURLGeneration()(ctx)
	case "/otp/secret":
		generateRandomSecret()(ctx)
	case "/":
		home()(ctx)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetBodyString("404 - Not Found")
	}
}
