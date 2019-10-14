package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
	"unsafe"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/micro/go-micro/web"
)

var (
	onlineUsers = make(map[string]bool)

	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

func PrintFormData(r *http.Request) {
	data := make(map[string]interface{})
	for k, v := range r.Form {
		data[k] = v
	}
	log.Printf("FormData: %v", data)
}

func TimeoutDialer(cTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, nil
	}
}

func PostJson(url string, data map[string]interface{}) (map[string]interface{}, error) {
	log.Printf("\nURL: %s,\nRequest: %v", url, data)
	bytesData, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	reader := bytes.NewReader(bytesData)
	request, err := http.NewRequest("POST", url, reader)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	client := http.Client{
		Transport: &http.Transport{
			Dial: TimeoutDialer(50*time.Second, 50*time.Second),
		},
	}
	resp, err := client.Do(request)
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
		"http://localhost:9002", "demoapp", "http://localhost:9003/login/callback", "1"), http.StatusFound)
}

func LoginCallbackHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	PrintFormData(r)
	code := r.FormValue("code")
	// state := r.FormValue("state")

	// 通过 code 取数据
	token, err := PostForm("http://localhost:9002/oauth/token", url.Values{
		"code":          {code},
		"client_id":     {"demoapp"},
		"client_secret": {"secret"},
		"redirect_uri":  {"http://localhost:9003/login/callback"},
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
	session, _ := store.Get(r, "cookie-name")
	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Values["accessToken"] = accessToken
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {

	// 通过 session 获取用户登录信息
	session, _ := store.Get(r, "cookie-name")

	// Check if user is authenticated
	auth, ok := session.Values["authenticated"].(bool)

	fmt.Fprintf(w, `<html><body><h1>Hello There</h1><p>Login Status: %v</p><a href="/login">Goto Login</a><br/><a href="/logout">Goto Logout</a></body></html>`, ok && auth)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	session, _ := store.Get(r, "cookie-name")

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
		web.Name("service.demoapp"),
		web.Handler(r),
		web.Address(":9003"),
	)

	if err := service.Init(); err != nil {
		log.Fatal(err)
	}

	if err := service.Run(); err != nil {
		log.Fatal(err)
	}
}
