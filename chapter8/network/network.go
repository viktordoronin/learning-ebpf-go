//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags -g network network.bpf.c
package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	//	"github.com/mdlayher/packet"
	"syscall"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

func main(){
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}
	//load objs
	var objs networkObjects
		if err:=loadNetworkObjects(&objs,nil); err!=nil{
			//log.Fatal("Loading eBPF objects:", err)
			var verr *ebpf.VerifierError
			if errors.As(err, &verr) {
			log.Fatalf("%+v\n", verr)
		}
	}
	defer objs.Close()

	//open kprobe for the TCP program
	kp, err := link.Kprobe("tcp_v4_connect", objs.Tcpconnect, nil)
	if err != nil {
		log.Fatalf("opening ksyscall: %s", err)
	}
	defer kp.Close()
	
	//open interface
	interf, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", "lo", err)
	}
	//
	myxdplink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Myxdp,
		Interface: interf.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer myxdplink.Close()

	//BCC version creates a raw socket and attaches the program to it
	//so we use a package: github.com/mdlayher/packet
	//this creates a raw socket at interface; 3rd argument is protocol type(IP in our case)
	// con,err:=packet.Listen(interf,packet.Raw,4,nil)
	// if err!=nil{
	// 	log.Fatal("opening raw socket:", err)
	// }
	fptr,err:=syscall.Socket(syscall.AF_INET,syscall.SOCK_RAW,syscall.IPPROTO_ICMP)
	if err!=nil{
		log.Fatal("opening raw socket:",err)
	}
	fd:=os.NewFile(uintptr(fptr),"raw socket")
	defer fd.Close()
  con,err:=net.FileConn(fd)
	if err!=nil{
		log.Fatal("opening connection from file")
	}
	defer con.Close()
	if err := link.AttachSocketFilter(con,objs.SocketFilter); err!=nil {
		log.Fatal("Attaching socket filter:", err)
	}

	// this uses another package in order to edit TC rules
	// open a rtnetlink socket
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Fatalf("could not open rtnetlink socket: %v\n", err)
		return
	}
	defer rtnl.Close()
	// this constructs a message to create a queueing discipline
	// for reference, in pyroute2 the order of args is command, kind, index, handle
	// here, we specify the latter 3, the actual command comes just after
	qdisc := tc.Object{
	tc.Msg{
		Family:  unix.AF_PACKET,
		Ifindex: uint32(interf.Index),
		Handle:  core.BuildHandle(0xFFFF, 0x0000),
		Parent:  0xFFFFFFF1,
		Info:    0,
	},
	tc.Attribute{
		Kind: "ingress",
	},
	}
	//now we add the qdisc to our TC
	if err := rtnl.Qdisc().Add(&qdisc); err!=nil{
		log.Fatalf("error adding qdisc:",err)
	}

	
	//the second TC rule has hit the program
	//this one is a lot more complicated so I'm not at all sure it's gonna work 
	addf:=tc.Object{
		tc.Msg{
			Family:  unix.AF_PACKET,
			Ifindex: uint32(interf.Index),
			Handle:  core.BuildHandle(0xFFFF, 0x0001),
			Parent:  0xFFFFFFF1,
			Info:    0,
		},
		tc.Attribute{
			Kind: "bpf",
		},
	}
	if err := rtnl.Filter().Add(&addf); err!=nil{
		log.Fatalf("error adding qdisc:",err)
	}
	//read data from socket filter
	for{
		//we remake the buffer each time for safety
		buf:=make([]byte,4096)
		num,_,err:= con.ReadFrom(buf)
		//bytes read are considered before error as per the doc
		if num>0{
			fmt.Printf("Userspace got data: %x",buf)
		}
		if err!=nil{
			log.Fatalf("error reading userspace packet:",err)
		}
		//flush the buffer
		buf=nil
	}
}
