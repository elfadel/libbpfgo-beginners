package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"os"
	"unsafe"
	"os/signal"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	bpfModule, err := bpf.NewModuleFromFile("hello.bpf.o")
	must(err)
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	must(err)	

	prog, err := bpfModule.GetProgram("hello")
	must(err)
	_, err = prog.AttachKprobe(sys_execve)
	must(err)

	sub_prog, err := bpfModule.GetProgram("sub_hello")
	must(err)
	sub_prog_fd := sub_prog.GetFd()

	prog_map, err := bpfModule.GetMap("prog_array")
	must(err)

	// Here, we can update first the main prog hello if necessary
	err = prog_map.Update(unsafe.Pointer(&sub1_prog_index), unsafe.Pointer(&sub_prog_fd))
	must(err)

	go bpf.TracePrint()

	<-sig
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
