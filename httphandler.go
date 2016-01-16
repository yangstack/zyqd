package zyqd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xuebing1110/queryapi"
	"net/http"
	"net/url"
	"regexp"
)

const (
	QD_URL      = "http://192.168.5.171:8009/nms/discp/login.jsp"
	REFER_URL   = "http://192.168.5.171:8009/nms/func.jsp"
	CODEIMG_URL = "http://192.168.5.171:8009/nms/discp/cryptogram.jsp"
	QDEXE_URL   = "http://192.168.5.171:8009/nms/discp/LoginExe.jsp"

	PATH_IMG    = `D:\Private Files\httpserv\htdocs\`
	FILE_COOKIE = `D:\Private Files\httpserv\cookies\192.168.5.171_8009.json`

	REG_STR_QD_NAME  = `(?s)name="NetUserID"\s*value="([^"]+)"`
	REG_STR_QD_IP    = `(?s)name="UserIP"\s*value="([^"]+)"`
	REG_STR_QD_DATE  = `(?s)name="LoginTime"\s*value="([^"]+)"`
	REG_STR_QD_ALERT = `(?s)alert\("([^"]+)"\);`

	RESP_RET_OK         = `0`
	RESP_RET_HTTPFAILED = `1`
	RESP_RET_SERVERR    = `2`
	RESP_ERRMSG_OK      = `ok`
)

var MYQDInfo *QDInfo
var REG_QD_NAME, REG_QD_IP, REG_QD_DATE, REG_QD_ALERT *regexp.Regexp

func init() {
	REG_QD_NAME = regexp.MustCompile(REG_STR_QD_NAME)
	REG_QD_IP = regexp.MustCompile(REG_STR_QD_IP)
	REG_QD_DATE = regexp.MustCompile(REG_STR_QD_DATE)
	REG_QD_ALERT = regexp.MustCompile(REG_STR_QD_ALERT)

	MYQDInfo = &QDInfo{}
}

type QDInfo struct {
	Name    string
	IP      string
	QDDate  string
	Remark  string
	Code    string
	Expire  bool
	CurDate int64
}

type QDResPonse struct {
	Ret    string
	ErrMsg string
}

func OpenHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ip := r.Form.Get("ip")

	var image_err error
	var image_bytes []byte
	if ip == "" || ip == "192.168.5.105" {
		image_bytes, image_err = HttpLocal()
	} else {
		image_bytes, image_err = HttpRemote(ip)
	}

	if image_err != nil {
		resp_json := &QDResPonse{
			Ret:    RESP_RET_HTTPFAILED,
			ErrMsg: image_err.Error(),
		}
		resp_json_b, _ := json.Marshal(resp_json)
		w.Write(resp_json_b)
	} else {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write(image_bytes)
	}
}

func CodeImgHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.Form.Get("code")

	v := url.Values{}
	v.Set("NetUserID", MYQDInfo.Name)
	v.Set("UserIP", MYQDInfo.IP)
	v.Set("LoginTime", MYQDInfo.QDDate)
	v.Set("Remark", " ")
	v.Set("cryptogram", code)

	exe_client := &queryapi.MyHttpClient{
		Method:         "POST",
		Url:            QDEXE_URL,
		Refer:          QD_URL,
		CookieFile:     FILE_COOKIE,
		SaveCookieFlag: false,
		PostData:       &v,
		ContentType:    `application/x-www-form-urlencoded`,
		Decode:         "gb2312",
	}

	resp_json := &QDResPonse{}
	http_err := exe_client.Do()
	if http_err != nil {
		resp_json.Ret = RESP_RET_HTTPFAILED
		resp_json.ErrMsg = http_err.Error()
	} else {
		matched_strs := REG_QD_ALERT.FindStringSubmatch(string(exe_client.ContentBytes))
		if len(matched_strs) == 2 {
			resp_json.Ret = RESP_RET_SERVERR
			resp_json.ErrMsg = matched_strs[1]
		} else {
			resp_json.Ret = RESP_RET_OK
			resp_json.ErrMsg = RESP_ERRMSG_OK
		}
	}

	resp_json_b, _ := json.Marshal(resp_json)
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.Write(resp_json_b)
}

func HttpLocal() ([]byte, error) {
	//open
	home_client := &queryapi.MyHttpClient{
		Method:         "GET",
		Url:            QD_URL,
		Refer:          REFER_URL,
		CookieFile:     FILE_COOKIE,
		SaveCookieFlag: true,
		ContentType:    "text/html;charset=gb2312",
	}
	http_err := home_client.Do()
	if http_err != nil {
		return home_client.ContentBytes, http_err
	}

	//截取页面信息
	matched_strs := REG_QD_NAME.FindStringSubmatch(string(home_client.ContentBytes))
	if len(matched_strs) != 2 {
		return home_client.ContentBytes, errors.New(fmt.Sprintf(`REG_QD_NAME Incorrect: "%s"`, matched_strs))
	}
	MYQDInfo.Name = matched_strs[1]

	matched_strs = REG_QD_IP.FindStringSubmatch(string(home_client.ContentBytes))
	if len(matched_strs) != 2 {
		return home_client.ContentBytes, errors.New(fmt.Sprintf(`REG_QD_IP Incorrect: "%s"`, matched_strs))
	}
	MYQDInfo.IP = matched_strs[1]

	matched_strs = REG_QD_DATE.FindStringSubmatch(string(home_client.ContentBytes))
	if len(matched_strs) != 2 {
		return home_client.ContentBytes, errors.New(fmt.Sprintf(`REG_QD_DATE Incorrect: "%s"`, matched_strs))
	}
	MYQDInfo.QDDate = matched_strs[1]

	//get content of image
	codeImg_client := &queryapi.MyHttpClient{
		Method:         "GET",
		Url:            CODEIMG_URL,
		Refer:          REFER_URL,
		CookieFile:     FILE_COOKIE,
		SaveCookieFlag: false,
		ContentType:    `text/html;charset=gb2312`,
	}
	http_err = codeImg_client.Do()
	return codeImg_client.ContentBytes, http_err
}

func HttpRemote(ip string) ([]byte, error) {
	//get content of image
	forward_client := &queryapi.MyHttpClient{
		Method:         "GET",
		Url:            "http://" + ip + ":10002/zyqd/open",
		Refer:          REFER_URL,
		SaveCookieFlag: false,
	}
	http_err := forward_client.Do()
	return forward_client.ContentBytes, http_err
}
