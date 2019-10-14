package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"unsafe"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/micro/go-micro/web"
)

var (
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)

	// it's port .
	PORT = "9004"

	ClientID = "demoapp2"

	ClientSecret = "secret"
)

func PrintFormData(r *http.Request) {
	data := make(map[string]interface{})
	for k, v := range r.Form {
		data[k] = v
	}
	log.Printf("FormData: %v", data)
}

func PostForm(url string, data url.Values) (map[string]interface{}, error) {
	log.Printf("\nURL: %s,\nRequest: %v", url, data)

	resp, err := http.PostForm(url, data)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	str := (*string)(unsafe.Pointer(&respBytes))
	log.Printf("\nResponse: %s", *str)
	var rspMap map[string]interface{}
	if err := json.Unmarshal(respBytes, &rspMap); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	return rspMap, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, fmt.Sprintf(`%s/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=read_userinfo&state=%s`,
		"http://localhost:9002", ClientID, "http://localhost:"+PORT+"/login/callback", "1"), http.StatusFound)
}

func LoginCallbackHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	PrintFormData(r)
	code := r.FormValue("code")
	// state := r.FormValue("state")

	// 通过 code 取数据
	token, err := PostForm("http://localhost:9002/oauth/token", url.Values{
		"code":          {code},
		"client_id":     {ClientID},
		"client_secret": {ClientSecret},
		"redirect_uri":  {"http://localhost:" + PORT + "/login/callback"},
		"grant_type":    {"authorization_code"},
		"scope":         {"read_userinfo"},
		"refresh_token": {""},
	})
	if err != nil {
		log.Println(err.Error())
		fmt.Fprintf(w, `<html><p>ERROR:%v</p></html>`, err)
		return
	}

	log.Println(token)
	accessToken, ok := token["access_token"]
	if !ok {
		log.Println(token["msg"])
		fmt.Fprintf(w, `<html><p>ERROR:%v</p></html>`, token["msg"])
		return
	}

	// set session
	session, _ := store.Get(r, "cookie-name-demoapp2")
	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Values["accessToken"] = accessToken
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {

	// 通过 session 获取用户登录信息
	session, _ := store.Get(r, "cookie-name-demoapp2")

	// Check if user is authenticated
	auth, ok := session.Values["authenticated"].(bool)

	fmt.Fprintf(w, `<html><body><h1>Hello There</h1><p>Login Status: %v</p><a href="/login">Goto Login</a><br/><a href="/logout">Goto Logout</a></body></html>`, ok && auth)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	session, _ := store.Get(r, "cookie-name-demoapp2")

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Values["accessToken"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/login/callback", LoginCallbackHandler)
	r.HandleFunc("/", IndexHandler)
	service := web.NewService(
		web.Name("service.demoapp2"),
		web.Handler(r),
		web.Address(":"+PORT),
	)

	if err := service.Init(); err != nil {
		log.Fatal(err)
	}

	if err := service.Run(); err != nil {
		log.Fatal(err)
	}
}
