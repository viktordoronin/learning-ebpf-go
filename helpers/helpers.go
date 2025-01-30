package helpers

import (
	"io"
	"os"
	"log"
)

func Trace_print(){ //BCC trace_print() equivalent
	r,err:=os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err!=nil{
		log.Fatal(err)
	}
	for{
		_,err=io.Copy(os.Stdout, r)
		if err!=nil{
			log.Fatal(err)
		}
	}
}
