package main

import (
	"fmt"
	"log"
	
	"github.com/cilium/ebpf"
)

func main(){
	findme, err:=ebpf.LoadPinnedMap("/sys/fs/bpf/findme", &ebpf.LoadPinOptions{ReadOnly:true})
	if err!=nil {
		log.Fatal(err)
	}
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
