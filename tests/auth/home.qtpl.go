// Code generated by qtc from "home.qtpl". DO NOT EDIT.
// See https://github.com/valyala/quicktemplate for details.

// Main page template. Implements basePage methods.
//

//line views/home.qtpl:3
package main

//line views/home.qtpl:3
import (
	qtio422016 "io"

	qt422016 "github.com/valyala/quicktemplate"
)

//line views/home.qtpl:3
var (
	_ = qtio422016.Copy
	_ = qt422016.AcquireByteBuffer
)

//line views/home.qtpl:4
type homePage struct {
	basePage
}

//line views/home.qtpl:10
func (x *homePage) StreamBody(qw422016 *qt422016.Writer) {
//line views/home.qtpl:10
	qw422016.N().S(`
`)
//line views/home.qtpl:11
	if x.IsAuthenticated() {
//line views/home.qtpl:11
		qw422016.N().S(`
<h1>Welcome `)
//line views/home.qtpl:12
		qw422016.E().S(x.Username)
//line views/home.qtpl:12
		qw422016.N().S(`</h1>
<div><a href="/account/logout">Logout</a></div>
`)
//line views/home.qtpl:14
	} else {
//line views/home.qtpl:14
		qw422016.N().S(`
<h1>Welcome Guest</h1>
`)
//line views/home.qtpl:16
	}
//line views/home.qtpl:16
	qw422016.N().S(`
`)
//line views/home.qtpl:17
}

//line views/home.qtpl:17
func (x *homePage) WriteBody(qq422016 qtio422016.Writer) {
//line views/home.qtpl:17
	qw422016 := qt422016.AcquireWriter(qq422016)
//line views/home.qtpl:17
	x.StreamBody(qw422016)
//line views/home.qtpl:17
	qt422016.ReleaseWriter(qw422016)
//line views/home.qtpl:17
}

//line views/home.qtpl:17
func (x *homePage) Body() string {
//line views/home.qtpl:17
	qb422016 := qt422016.AcquireByteBuffer()
//line views/home.qtpl:17
	x.WriteBody(qb422016)
//line views/home.qtpl:17
	qs422016 := string(qb422016.B)
//line views/home.qtpl:17
	qt422016.ReleaseByteBuffer(qb422016)
//line views/home.qtpl:17
	return qs422016
//line views/home.qtpl:17
}