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
	CHECK_URL   = "http://192.168.5.171:8009/nms/discp/SignList.jsp"

	PATH_IMG    = `D:\Private Files\httpserv\htdocs\`
	FILE_COOKIE = `D:\Private Files\httpserv\cookies\192.168.5.171_8009.json`

	REG_STR_QD_NAME  = `(?s)name="NetUserID"\s*value="([^"]+)"`
	REG_STR_QD_IP    = `(?s)name="UserIP"\s*value="([^"]+)"`
	REG_STR_QD_DATE  = `(?s)name="LoginTime"\s*value="([^"]+)"`
	REG_STR_QD_ALERT = `(?s)alert\("([^"]+)"\);`
	REG_STR_QD_CHECK = `(?s)class="listrownew".*?<nobr>([^<]*\S)\s*<\/nobr>.*?<nobr>([^<]*\S)\s*<\/nobr>.*?<nobr>([^<]*\S)\s*<\/nobr>.*?<nobr>([^<]*\S)\s*<\/nobr>.*?<nobr>(周[^<]*\S)\s*<\/nobr>`

	RESP_RET_OK         = `0`
	RESP_RET_HTTPFAILED = `10001`
	RESP_RET_FORWARDERR = `20001`
	RESP_RET_SERVERR    = `30001`
	RESP_ERRMSG_OK      = `ok`
)

var MYQDInfo *QDInfo
var REG_QD_NAME, REG_QD_IP, REG_QD_DATE, REG_QD_ALERT, REG_QD_CHECK *regexp.Regexp

func init() {
	REG_QD_NAME = regexp.MustCompile(REG_STR_QD_NAME)
	REG_QD_IP = regexp.MustCompile(REG_STR_QD_IP)
	REG_QD_DATE = regexp.MustCompile(REG_STR_QD_DATE)
	REG_QD_ALERT = regexp.MustCompile(REG_STR_QD_ALERT)
	REG_QD_CHECK = regexp.MustCompile(REG_STR_QD_CHECK)

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
	Status  string
	WeekDay string
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
		image_bytes, image_err = HttpLocal_open()
	} else {
		image_bytes, image_err = HttpRemote_open(ip)
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

func CloseHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.Form.Get("code")
	ip := r.Form.Get("ip")

	v := url.Values{}
	v.Set("NetUserID", MYQDInfo.Name)
	v.Set("UserIP", MYQDInfo.IP)
	v.Set("LoginTime", MYQDInfo.QDDate)
	v.Set("Remark", " ")
	v.Set("cryptogram", code)

	var resp_json *QDResPonse
	if ip == "" || ip == "192.168.5.105" {
		resp_json = HttpLocal_close(code)
	} else {
		resp_json = HttpRemote_close(code, ip)
	}

	resp_json_b, _ := json.Marshal(resp_json)
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.Write(resp_json_b)
}

func HttpLocal_close(code string) *QDResPonse {
	resp_json := &QDResPonse{}

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

	//send http request
	http_err := exe_client.Do()
	if http_err != nil {
		resp_json.Ret = RESP_RET_HTTPFAILED
		resp_json.ErrMsg = http_err.Error()
	} else {
		//http response
		matched_strs := REG_QD_ALERT.FindStringSubmatch(string(exe_client.ContentBytes))
		if len(matched_strs) == 2 {
			resp_json.Ret = RESP_RET_SERVERR
			resp_json.ErrMsg = matched_strs[1]
		} else {
			resp_json.Ret = RESP_RET_OK
			resp_json.ErrMsg = RESP_ERRMSG_OK
		}
	}

	//检查是否成功
	if MYQDInfo.CheckSign() == nil {
		resp_json.Ret = RESP_RET_OK
		resp_json.ErrMsg = fmt.Sprintf("姓名：%v\n状态：%v\n周几：%v\nIP地址：%v\n签到时间：%v",
			MYQDInfo.Name, MYQDInfo.Status,
			MYQDInfo.WeekDay, MYQDInfo.IP,
			MYQDInfo.QDDate,
		)
	}

	return resp_json
}

func HttpRemote_close(code, ip string) *QDResPonse {
	resp_json := &QDResPonse{}

	//get content of image
	forward_client := &queryapi.MyHttpClient{
		Method:         "GET",
		Url:            "http://" + ip + ":10002/zyqd/close?code=" + code,
		Refer:          REFER_URL,
		SaveCookieFlag: false,
	}

	//send http request
	http_err := forward_client.Do()
	if http_err != nil {
		resp_json.Ret = RESP_RET_FORWARDERR
		resp_json.ErrMsg = http_err.Error()
	} else {
		parse_err := json.Unmarshal(forward_client.ContentBytes, resp_json)
		if parse_err != nil {
			resp_json.Ret = RESP_RET_SERVERR
			resp_json.ErrMsg = parse_err.Error()
		}
	}

	return resp_json
}

func (user_qd *QDInfo) CheckSign() error {
	var check_url string
	if user_qd.IP == "" {
		check_url = CHECK_URL + "?UserIP=192.168.5.105"
	} else {
		check_url = CHECK_URL + "?UserIP=" + user_qd.IP
	}

	check_client := &queryapi.MyHttpClient{
		Method:      "GET",
		Url:         check_url,
		Refer:       REFER_URL,
		CookieFile:  FILE_COOKIE,
		Decode:      "GB2312",
		ContentType: "text/html;charset=gb2312",
	}
	http_err := check_client.Do()
	if http_err != nil {
		return http_err
	}

	matched_strs := REG_QD_CHECK.FindStringSubmatch(string(check_client.ContentBytes))
	if len(matched_strs) != 6 {
		return errors.New("今天还未签到！")
	}

	user_qd.Status = matched_strs[1]
	user_qd.Name = matched_strs[2]
	user_qd.IP = matched_strs[3]
	user_qd.QDDate = matched_strs[4]
	user_qd.WeekDay = matched_strs[5]

	return nil
}

func HttpLocal_open() ([]byte, error) {
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

func HttpRemote_open(ip string) ([]byte, error) {
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
