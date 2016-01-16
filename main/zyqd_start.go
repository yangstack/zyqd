package main

import (
	"github.com/xuebing1110/zyqd"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/zyqd/open", zyqd.OpenHandler)
	http.HandleFunc("/zyqd/close", zyqd.CodeImgHandler)

	log.Println("listen 10002...")
	log.Panicln(http.ListenAndServe(":10002", nil))
}
