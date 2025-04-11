package main

import (
	"fmt"
	"log"
	
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/pin"
)

func main(){
	pinner, err:=pin.Load("/sys/fs/bpf/findme", &ebpf.LoadPinOptions{ReadOnly:true})
	if err!=nil {
		log.Fatal(err)
	}
	findme,_ := pinner.(*ebpf.Map)
	if findme == nil {
		fmt.Println("No FD")
	} else {
		info,err:=findme.Info()
		if err!=nil {
			log.Fatal(err)
		}
		fmt.Printf("Name: %s\n",info.Name)
	}
}
