package resultor

import (
	"fmt"
	"github.com/pquerna/ffjson/ffjson"
	"net/http"
	"reflect"
)

var ErrList = map[string]string{
	"1001": "没有收到提交内容",
	"1002": "防注入生效",
	"1003": "参数错误或objectid类型错误",
}

func RetChanges(w http.ResponseWriter, changes int64) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	fmt.Fprintf(w, `{"ok":%v,"changes":%v}`, true, changes)
}

func RetOk(w http.ResponseWriter, result interface{}, changes int) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	resValue := reflect.ValueOf(result)
	if result == nil {
		RetChanges(w, 0)
		return
	}
	if resValue.Kind() == reflect.Ptr {
		resValue = resValue.Elem()
	}
	var res interface{}
	if resValue.Kind() == reflect.Array || resValue.Kind() == reflect.Slice {
		res = result
	} else {
		res = []interface{}{result}
	}
	bytes, _ := ffjson.Marshal(res)
	fmt.Fprintf(w, `{"ok":%v,"changes":%v,"data":%v}`, true, changes, string(bytes))
}

func RetErr(w http.ResponseWriter, errmsg interface{}) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	if _, ok := ErrList[errmsg.(string)]; ok {
		fmt.Fprintf(w, `{"ok":%v, "errcode":%v, "errmsg":"%v"}`, false, errmsg, ErrList[errmsg.(string)])
	} else {
		fmt.Fprintf(w, `{"ok":%v, "errmsg":"%v"}`, false, errmsg)
	}
}
