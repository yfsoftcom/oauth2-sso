package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/micro/go-micro/web"
)

var (
	key   = []byte("oauth-key")
	store = sessions.NewCookieStore(key)
)

func RenderJSON(w http.ResponseWriter, httpCode int, b []byte) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	w.Write(b)
}

func PrintFormData(r *http.Request) {
	data := make(map[string]interface{})
	for k, v := range r.Form {
		data[k] = v
	}
	log.Printf("FormData: %v", data)
}

// 验证权限的接口1
// http://localhost:9002/oauth/authorize?client_id=demoapp&response_type=code&redirect_uri=http://localhost:3333&scope=read_userinfo&state=2
func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	PrintFormData(r)
	clientID := r.FormValue("client_id")
	responseType := r.FormValue("response_type")

	// display := r.FormValue("display")
	// language := r.FormValue("language")

	// check clientid and redirectURI

	if "demoapp" != clientID && "demoapp2" != clientID {
		RenderJSON(w, 401, []byte(fmt.Sprintf(`{"msg":"clientID:%s 未授权"}`, clientID)))
		return
	}

	if "code" != responseType {
		RenderJSON(w, 401, []byte(`{"msg":"response_type必须是 code"}`))
		return
	}

	// check scope

	session, _ := store.Get(r, "cookie-name-oauth2")

	if r.Method == "GET" {
		// Check if user is authenticated
		rememberme, ok := session.Values["rememberme"].(string)

		// log.Printf("rememberme from session: %s, ok: %v", rememberme, ok)
		if !ok || rememberme != "1" {
			// 跳转到页面
			fmt.Fprint(w, `<html>
			<form method="POST">
				<label>User: </label><input name="username"/><br/>
				<label>Pass: </label><input name="password"/><br/>
				<label>Remember Me: </label><input name="rememberme" type="checkbox" value="1"/><br/>
				<input type="submit" />
			</form>
			</html>`)
			return
		}
		username, ok := session.Values["username"].(string)
		password, ok := session.Values["password"].(string)
		// 跳转到页面
		fmt.Fprintf(w, `<html>
			<form method="POST">
				<label>User: </label><input name="username" value="%s"/><br/>
				<label>Pass: </label><input name="password" value="%s"/><br/>
				<label>Remember Me: </label><input name="rememberme" type="checkbox" value="1" checked /><br/>
				<input type="submit" />
			</form>
			</html>`, username, password)

		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	rememberme := r.FormValue("rememberme")
	if !(username == "test" && password == "test") {
		RenderJSON(w, 402, []byte(`用户名密码错误：试试使用 test`))
		return
	}
	log.Printf("login ok ,save session: rememberme %v", rememberme == "1")
	if rememberme == "1" {
		// set cookie
		session.Values["username"] = username
		session.Values["password"] = password
		session.Values["rememberme"] = rememberme
		session.Save(r, w)
	}

	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")

	http.Redirect(w, r, fmt.Sprintf(`%s?&scope=%s&state=%s&code=%s`, redirectURI, scope, state, "foobar"), http.StatusFound)
}

func TokenHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	PrintFormData(r)
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	// redirectURI := r.FormValue("redirect_uri")
	grantType := r.FormValue("grant_type")
	scope := r.FormValue("scope")

	// refreshToken := r.FormValue("refresh_token")

	if "demoapp" != clientID && "demoapp2" != clientID {
		RenderJSON(w, 401, []byte(fmt.Sprintf(`{"msg":"clientID:%s 未授权"}`, clientID)))
		return
	}

	if "secret" != clientSecret {
		RenderJSON(w, 401, []byte(fmt.Sprintf(`{"msg":"clientSecret:%s 未授权"}`, clientSecret)))
		return
	}

	if "authorization_code" == grantType {
		// code := r.FormValue("code")
		RenderJSON(w, 200, []byte(fmt.Sprintf(`{"access_token":"%s","expires_in":100,"scope":"%s","token_type":"bearer","access_token":"%s"}`,
			"foo", scope, "foo_refresh")))
		return
	}

	if "refresh_token" == grantType {
		// refreshToken := r.FormValue("refresh_token")
		RenderJSON(w, 200, []byte(fmt.Sprintf(`{"access_token":%s,"expires_in":100,"scope":%s,"token_type":"bearer","access_token":%s}`,
			"foo", scope, "foo_refresh")))
		return
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/oauth/authorize", AuthorizeHandler)
	r.HandleFunc("/oauth/token", TokenHandler)
	r.HandleFunc("/oauth/confirm", AuthorizeHandler)
	r.HandleFunc("/oauth/check", AuthorizeHandler)
	service := web.NewService(
		web.Name("service.oauth"),
		web.Handler(r),
		web.Address(":9002"),
	)

	if err := service.Init(); err != nil {
		log.Fatal(err)
	}

	if err := service.Run(); err != nil {
		log.Fatal(err)
	}
}
