package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket)")
	tpmPass = flag.String("tpm-pass", "", "TPM device password (if needed)")
	index   = flag.Uint("index", 0, "NVRAM index of read")
)

func main() {
	flag.Parse()

	if *index == 0 {
		fmt.Fprintln(os.Stderr, "--index must be set")
		os.Exit(1)
	}

	val, err := nvRead(*tpmPath, *tpmPass, uint32(*index))
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading from index 0x%x: %v\n", *index, err)
		os.Exit(1)
	}

	fmt.Printf("NVRAM value at index 0x%x (hex encoded):\n%x\n", *index, val)
}

func nvRead(path string, auth string, index uint32) ([]byte, error) {
	rw, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM at %q: %v", path, err)
	}
	defer rw.Close()

	nv, err := tpm2.NVReadEx(rw, tpmutil.Handle(index), tpm2.HandleOwner, auth, 0)
	if err != nil {
		return nil, err
	}

	return nv, nil
}
