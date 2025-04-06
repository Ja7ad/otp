package api

import (
	"github.com/valyala/fasthttp"
	"log/slog"
	"runtime"
	"strings"
	"time"
)

// Middleware defines the middleware function signature for fasthttp
type Middleware func(fasthttp.RequestHandler) fasthttp.RequestHandler

// Chain applies multiple middleware functions to a fasthttp handler
func Chain(middlewares ...Middleware) Middleware {
	return func(final fasthttp.RequestHandler) fasthttp.RequestHandler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

func Recovery(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		defer func() {
			if r := recover(); r != nil {
				stack := captureStackTrace(3)
				slog.Error("panic recovered",
					slog.Any("error", r),
					slog.String("path", string(ctx.Path())),
					slog.Any("stack", stack),
				)
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
				ctx.SetBodyString("Internal Server Error")
			}
		}()
		next(ctx)
	}
}

func Logger(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		start := time.Now()
		next(ctx)
		duration := time.Since(start)

		slog.Info("request",
			slog.String("method", string(ctx.Method())),
			slog.String("path", string(ctx.Path())),
			slog.Int("status", ctx.Response.StatusCode()),
			slog.Duration("duration", duration),
		)
	}
}

// captureStackTrace formats the stack trace in a structured and readable way
func captureStackTrace(skip int) []map[string]any {
	var pcs [32]uintptr
	n := runtime.Callers(skip, pcs[:])

	var stackTrace []map[string]any
	frames := runtime.CallersFrames(pcs[:n])

	for {
		frame, more := frames.Next()
		// Skip runtime internal frames
		if !strings.Contains(frame.File, "runtime/") {
			stackTrace = append(stackTrace, map[string]any{
				"function": frame.Function,
				"file":     frame.File,
				"line":     frame.Line,
			})
		}
		if !more {
			break
		}
	}

	return stackTrace
}
