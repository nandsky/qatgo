/*
HASH接口
*/
package hash

// #include <stdlib.h>
// #include <qat.h>
// #include <cipher.h>
// #cgo CFLAGS: -I../src -I../lib/qat
// #cgo LDFLAGS: -L.. -L../output -licp_qa_al_s -lqatgo
import "C"

import (
	"fmt"
)

func TestMD5() {

	fmt.Println("hello QAT!")
	plainTxt := "hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!"

	arr := make([]C.uchar, 0)

	for i := 0; i < len(plainTxt); i++ {
		arr = append(arr, C.uchar(plainTxt[i]))
	}

	md := make([]C.uchar, 16)

	C.qat_init()
	C.MD5(&arr[0], C.uint(len(arr)), &md[0])

	fmt.Println(md)
	C.qat_exit()

}
