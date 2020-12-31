// Code generated by qtc from "login.qtpl". DO NOT EDIT.
// See https://github.com/valyala/quicktemplate for details.

// Main page template. Implements basePage methods.
//

//line views/login.qtpl:3
package main

//line views/login.qtpl:3
import (
	qtio422016 "io"

	qt422016 "github.com/valyala/quicktemplate"
)

//line views/login.qtpl:3
var (
	_ = qtio422016.Copy
	_ = qt422016.AcquireByteBuffer
)

//line views/login.qtpl:4
type loginPage struct {
	basePage
	ReturnURL string
	Error     string
}

//line views/login.qtpl:12
func (p *loginPage) StreamBody(qw422016 *qt422016.Writer) {
//line views/login.qtpl:12
	qw422016.N().S(`
<div class="login-form">
<form class="form-signin" action="/account/login?returnUrl=`)
//line views/login.qtpl:14
	qw422016.E().S(p.ReturnURL)
//line views/login.qtpl:14
	qw422016.N().S(`" method="post">
<div class="avatar"><i class="far fa-user"></i></div>
<h4 class="modal-title">Login to Your Account</h4>
<div class="form-group">
<input type="text" name="Username" class="form-control" placeholder="Username" required autofocus />
</div>
<div class="form-group">
<input type="password" name="Password" class="form-control" placeholder="Password" required />
</div>
<div class="form-group small clearfix">
<label class="checkbox-inline"><input type="checkbox" name="RememberLogin" value="true" /> Remember me</label>
</div>
<button type="submit" class="btn btn-primary btn-block btn-lg" value="Login">Login</button>
<input id="Token" name="Token" type="hidden" />
</form>
`)
//line views/login.qtpl:29
	if p.Error != "" {
//line views/login.qtpl:29
		qw422016.N().S(`
<div class="error">`)
//line views/login.qtpl:30
		qw422016.E().S(p.Error)
//line views/login.qtpl:30
		qw422016.N().S(`</div>
`)
//line views/login.qtpl:31
	}
//line views/login.qtpl:31
	qw422016.N().S(`
</div>
`)
//line views/login.qtpl:33
}

//line views/login.qtpl:33
func (p *loginPage) WriteBody(qq422016 qtio422016.Writer) {
//line views/login.qtpl:33
	qw422016 := qt422016.AcquireWriter(qq422016)
//line views/login.qtpl:33
	p.StreamBody(qw422016)
//line views/login.qtpl:33
	qt422016.ReleaseWriter(qw422016)
//line views/login.qtpl:33
}

//line views/login.qtpl:33
func (p *loginPage) Body() string {
//line views/login.qtpl:33
	qb422016 := qt422016.AcquireByteBuffer()
//line views/login.qtpl:33
	p.WriteBody(qb422016)
//line views/login.qtpl:33
	qs422016 := string(qb422016.B)
//line views/login.qtpl:33
	qt422016.ReleaseByteBuffer(qb422016)
//line views/login.qtpl:33
	return qs422016
//line views/login.qtpl:33
}

//line views/login.qtpl:35
func (p *loginPage) StreamScripts(qw422016 *qt422016.Writer) {
//line views/login.qtpl:35
	qw422016.N().S(`
<script src="https://www.google.com/recaptcha/api.js?render=6LcATMAUAAAAAFKGtk5ki6zJ9gnZguO_58fJUNS6"></script>
<script>grecaptcha.ready(function () {grecaptcha.execute('6LcATMAUAAAAAFKGtk5ki6zJ9gnZguO_58fJUNS6', {action: 'login'}).then(function (token) {$("#Token").val(token);});});</script>
`)
//line views/login.qtpl:38
}

//line views/login.qtpl:38
func (p *loginPage) WriteScripts(qq422016 qtio422016.Writer) {
//line views/login.qtpl:38
	qw422016 := qt422016.AcquireWriter(qq422016)
//line views/login.qtpl:38
	p.StreamScripts(qw422016)
//line views/login.qtpl:38
	qt422016.ReleaseWriter(qw422016)
//line views/login.qtpl:38
}

//line views/login.qtpl:38
func (p *loginPage) Scripts() string {
//line views/login.qtpl:38
	qb422016 := qt422016.AcquireByteBuffer()
//line views/login.qtpl:38
	p.WriteScripts(qb422016)
//line views/login.qtpl:38
	qs422016 := string(qb422016.B)
//line views/login.qtpl:38
	qt422016.ReleaseByteBuffer(qb422016)
//line views/login.qtpl:38
	return qs422016
//line views/login.qtpl:38
}