package main

import (
	oauth2 "github.com/Lukiya/oauth2go/core"
	"github.com/valyala/fasthttp"
)

func writePage(ctx *fasthttp.RequestCtx, view Page) {
	ctx.SetContentType(oauth2.ContentType_Html)
	WritePageTemplate(ctx, view)
}
