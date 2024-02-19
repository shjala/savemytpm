// Quick and dirty tool, written in a span of a day,
// to make some machines happpy.

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/api/go/attest"
	"google.golang.org/protobuf/proto"
)

var (
	tpmPath         = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket)")
	tpmPass         = flag.String("tpm-pass", "", "TPM device password (if needed)")
	pubIndex        = flag.Uint("pub-index", 0, "Disk key public key NVRAM index")
	privIndex       = flag.Uint("priv-index", 0, "Disk Key private key NVRAM index")
	srkIndex        = flag.Uint("srk-index", 0, "SRK index")
	ecdhIndex       = flag.Uint("ecdh-index", 0, "ECDH index")
	certIndex       = flag.Uint("cert-index", 0, "Device Cert index")
	certPath        = flag.String("cert-path", "", "Path to the device cert file")
	pcrHash         = flag.String("pcr-hash", "sha1", "PCR Hash algorithm (sha1, sha256)")
	pcrIndexes      = flag.String("pcr-index", "0, 1, 2, 3, 4, 6, 7, 8, 9, 13", "PCR Indexes to use for sealing and unsealing")
	exportPlain     = flag.Bool("export-plain", false, "Export the disk key in plain text")
	exportCloud     = flag.Bool("export-cloud", false, "Export the disk key in cloud encrypted form")
	exportEncrypted = flag.Bool("export-encrypted", false, "Export the disk key in encrypted form")
	importPlain     = flag.Bool("import-plain", false, "Import the disk key in plain text")
	importEncrypted = flag.Bool("import-encrypted", false, "Import the disk key in encrypted form")
	reseal          = flag.Bool("reseal", false, "Reseal the disk key under new PCR indexes and hash algorithm")
	output          = flag.String("output", "", "Output file for the disk key")
	input           = flag.String("input", "", "Input file for the disk key")
	tpmInfo         = flag.Bool("tpm-info", false, "Print TPM information")
	checkCert       = flag.Bool("check-cert", false, "Check the device cert from disk against the TPM")
)

func main() {
	initArgs()

	if *tpmInfo {
		info, err := fetchTpmHwInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when fetching TPM info: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] TPM Info: %s\n", info)
		return
	}

	if *checkCert {
		tpmPublicKey, err := readDevicePubFromTPM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when reading DevicePub from TPM: %v\n", err)
			os.Exit(1)
		}

		filePublicKey, err := readDevicePubFromFile(*certPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when reading DevicePub from file: %v\n", err)
			os.Exit(1)
		}

		if reflect.DeepEqual(tpmPublicKey, filePublicKey) {
			fmt.Printf("[+] Device cert matches TPM cert\n")
		} else {
			fmt.Printf("[-] Device cert does not match TPM cert\n")
		}

		return
	}

	hashAlgo := tpm2.AlgSHA1
	if *pcrHash == "sha256" {
		hashAlgo = tpm2.AlgSHA256
	}

	pcrs, err := getPcrIndexes(strings.Split(*pcrIndexes, ","))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error when parsing pcr-indexes: %v\n", err)
		os.Exit(1)
	}

	diskKey := make([]byte, 0)
	if *exportEncrypted || *exportCloud || *exportPlain {
		pcrSel := tpm2.PCRSelection{Hash: hashAlgo, PCRs: pcrs}
		diskKey, err = getDiskKey(uint32(*privIndex), uint32(*pubIndex), uint32(*srkIndex), pcrSel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when reading from the disk key: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Disk key available and exportable.\n")
	}

	// Export the disk key to the output file in plain text
	if *exportPlain && *output != "" {
		fmt.Printf("[+] Saving disk key to %s\n", *output)
		if err := os.WriteFile(string(*output), diskKey, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error when writing to the output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] disk key saved.\n")
	}

	if *exportCloud && *output != "" {
		fmt.Printf("[+] Saving cloud-format encrypted disk key...\n")

		encryptedDiskKey, err := encryptDecryptUsingTpm(diskKey, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when encrypting disk key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(string(*output)+".raw", encryptedDiskKey, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error when writing raw formatted key to the output file: %v\n", err)
			os.Exit(1)
		}

		hash := sha256.New()
		hash.Write(diskKey)
		digest256 := hash.Sum(nil)

		keyData := &attest.AttestVolumeKeyData{
			EncryptedKey: encryptedDiskKey,
			DigestSha256: digest256,
		}

		encryptedVaultKey, err := proto.Marshal(keyData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when marshaling AttestVolumeKeyData %v", err)
			os.Exit(1)
		}

		key := new(attest.AttestVolumeKey)
		key.KeyType = attest.AttestVolumeKeyType_ATTEST_VOLUME_KEY_TYPE_VSK
		key.Key = encryptedVaultKey

		volumeKey, err := proto.Marshal(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when marshaling AttestVolumeKey %v", err)
			os.Exit(1)
		}

		cloudDbFormat := fmt.Sprintf("0x%X", volumeKey)
		if err := os.WriteFile(string(*output)+".txt", []byte(cloudDbFormat), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error when writing cloud formatted key to the output file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] disk key saved.\n")
	}

	if *reseal {
		fmt.Printf("[!] not implemented yet...\n")
		return
	}

	if *importPlain || *importEncrypted {
		fmt.Printf("[!] not implemented yet...\n")
		return
	}

	// TODO :
	// Import the disk key from the input file
	// Reseal the disk key under new PCR indexes and hash algorithm
}

func initArgs() {
	flag.Parse()

	if *checkCert {
		if *certPath == "" && *certIndex == 0 {
			fmt.Fprintln(os.Stderr, "cert-path and cert-index must be specified for check-cert")
			os.Exit(1)
		}
	} else {
		if *exportPlain == false && *exportEncrypted == false && *importPlain == false && *importEncrypted == false && *reseal == false && *exportCloud == false {
			fmt.Fprintln(os.Stderr, "One of export-*/import-* or reseal must be specified")
			os.Exit(1)
		}

		if (*importPlain || *importEncrypted) && *input == "" {
			fmt.Fprintln(os.Stderr, "import commands requires input to be specified")
			os.Exit(1)
		}

		if *importPlain && *importEncrypted {
			fmt.Fprintln(os.Stderr, "import-plain and import-encrypted are mutually exclusive")
			os.Exit(1)
		}

		if *pubIndex == 0 || *privIndex == 0 || *srkIndex == 0 {
			fmt.Fprintln(os.Stderr, "pub-index, priv-index and srk-index must be non-zero")
			os.Exit(1)
		}

		if *pcrHash != "sha1" && *pcrHash != "sha256" {
			fmt.Fprintln(os.Stderr, "pcr-hash must be sha1 or sha256")
			os.Exit(1)
		}

		if *pcrIndexes == "" {
			fmt.Fprintln(os.Stderr, "pcr-indexes must be non-empty")
			os.Exit(1)
		}

		if *exportCloud && *output == "" {
			fmt.Fprintln(os.Stderr, "output must be specified for export-cloud")
			os.Exit(1)
		}

		if *exportCloud && *certIndex == 0 {
			fmt.Fprintln(os.Stderr, "cert-index must be non-zero for export-cloud")
			os.Exit(1)
		}
	}
}

const (
	tpmPropertyManufacturer tpm2.TPMProp = 0x105
	tpmPropertyVendorStr1   tpm2.TPMProp = 0x106
	tpmPropertyVendorStr2   tpm2.TPMProp = 0x107
	tpmPropertyFirmVer1     tpm2.TPMProp = 0x10b
	tpmPropertyFirmVer2     tpm2.TPMProp = 0x10c
)

var vendorRegistry = map[uint32]string{
	0x414D4400: "AMD",
	0x41544D4C: "Atmel",
	0x4252434D: "Broadcom",
	0x48504500: "HPE",
	0x49424d00: "IBM",
	0x49465800: "Infineon",
	0x494E5443: "Intel",
	0x4C454E00: "Lenovo",
	0x4D534654: "Microsoft",
	0x4E534D20: "National SC",
	0x4E545A00: "Nationz",
	0x4E544300: "Nuvoton",
	0x51434F4D: "Qualcomm",
	0x534D5343: "SMSC",
	0x53544D20: "ST Microelectronics",
	0x534D534E: "Samsung",
	0x534E5300: "Sinosun",
	0x54584E00: "Texas Instruments",
	0x57454300: "Winbond",
	0x524F4343: "Fuzhou Rockchip",
	0x474F4F47: "Google",
}

// GetTpmProperty fetches a given property id, and returns it as uint32
func getTpmProperty(propID tpm2.TPMProp) (uint32, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return 0, err
	}
	defer rw.Close()

	v, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties,
		1, uint32(propID))
	if err != nil {
		return 0, err
	}
	prop, ok := v[0].(tpm2.TaggedProperty)
	if !ok {
		return 0, fmt.Errorf("fetching TPM property %X failed", propID)
	}
	return prop.Value, nil
}

func getModelName(vendorValue1 uint32, vendorValue2 uint32) string {
	uintToByteArr := func(value uint32) []byte {
		get8 := func(val uint32, offset uint32) uint8 {
			return (uint8)((val >> ((3 - offset) * 8)) & 0xff)
		}
		var i uint32
		var bytes []byte
		for i = 0; i < uint32(unsafe.Sizeof(value)); i++ {
			c := get8(value, i)
			bytes = append(bytes, c)
		}
		return bytes
	}
	var model []byte
	model = append(model, uintToByteArr(vendorValue1)...)
	model = append(model, uintToByteArr(vendorValue2)...)
	return string(model)
}

func getFirmwareVersion(v1 uint32, v2 uint32) string {
	get16 := func(val uint32, offset uint32) uint16 {
		return uint16((val >> ((1 - offset) * 16)) & 0xFFFF)
	}
	return fmt.Sprintf("%d.%d.%d.%d", get16(v1, 0), get16(v1, 1),
		get16(v2, 0), get16(v2, 1))
}

func fetchTpmHwInfo() (string, error) {
	tpmHwInfo := ""
	//Take care of non-TPM platforms
	if _, err := os.Stat(*tpmPath); err != nil {
		tpmHwInfo = "Not Available"
		//nolint:nilerr
		return tpmHwInfo, nil
	}

	//First time. Fetch it from TPM and cache it.
	v1, err := getTpmProperty(tpmPropertyManufacturer)
	if err != nil {
		return "", err
	}
	v2, err := getTpmProperty(tpmPropertyVendorStr1)
	if err != nil {
		return "", err
	}
	v3, err := getTpmProperty(tpmPropertyVendorStr2)
	if err != nil {
		return "", err
	}
	v4, err := getTpmProperty(tpmPropertyFirmVer1)
	if err != nil {
		return "", err
	}
	v5, err := getTpmProperty(tpmPropertyFirmVer2)
	if err != nil {
		return "", err
	}
	tpmHwInfo = fmt.Sprintf("%s-%s, FW Version %s", vendorRegistry[v1],
		getModelName(v2, v3),
		getFirmwareVersion(v4, v5))

	return tpmHwInfo, nil
}

func getPcrIndexes(pcrs []string) ([]int, error) {
	var pcrIndexes []int
	for _, pcr := range pcrs {
		index, err := strconv.Atoi(strings.TrimSpace(pcr))
		if err != nil {
			return nil, fmt.Errorf("invalid PCR index: %v %v", pcr, err)
		}
		pcrIndexes = append(pcrIndexes, index)
	}
	return pcrIndexes, nil
}

func policyPCRSession(rw io.ReadWriteCloser, pcrSel tpm2.PCRSelection) (tpmutil.Handle, []byte, error) {
	session, _, err := tpm2.StartAuthSession(
		rw,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ make([]byte, 16),
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("StartAuthSession failed: %v", err)
	}
	defer func() {
		if session != tpm2.HandleNull && err != nil {
			tpm2.FlushContext(rw, session)
		}
	}()

	if err = tpm2.PolicyPCR(rw, session, nil, pcrSel); err != nil {
		return session, nil, fmt.Errorf("PolicyPCR failed: %v", err)
	}

	policy, err := tpm2.PolicyGetDigest(rw, session)
	if err != nil {
		return session, nil, fmt.Errorf("Unable to get policy digest: %v", err)
	}
	return session, policy, nil
}

func getDiskKey(diskKeyPriv uint32, diskKeyPub uint32, tpmSRK uint32, pcrSel tpm2.PCRSelection) ([]byte, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	priv, err := tpm2.NVReadEx(rw, tpmutil.Handle(diskKeyPriv),
		tpm2.HandleOwner, *tpmPass, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %v", diskKeyPriv, err)
	}

	pub, err := tpm2.NVReadEx(rw, tpmutil.Handle(diskKeyPub),
		tpm2.HandleOwner, *tpmPass, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %v", diskKeyPub, err)
	}

	sealedObjHandle, _, err := tpm2.Load(rw, tpmutil.Handle(tpmSRK), "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("Load failed: %v", err)
	}
	defer tpm2.FlushContext(rw, sealedObjHandle)

	session, _, err := policyPCRSession(rw, pcrSel)
	if err != nil {
		return nil, fmt.Errorf("policyPCRSession failed: %v", err)
	}
	defer tpm2.FlushContext(rw, session)

	key, err := tpm2.UnsealWithSession(rw, session, sealedObjHandle, *tpmPass)
	if err != nil {
		return nil, fmt.Errorf("UnsealWithSession failed: %v", err)
	}
	return key, nil
}

func aesEncrypt(ciphertext, plaintext, key, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(ciphertext, plaintext)
	return nil
}

func aesDecrypt(plaintext, ciphertext, key, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("creating aes new cipher failed: %v", err)
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(plaintext, ciphertext)
	return nil
}

func ecdsakeyBytes(pubKey *ecdsa.PublicKey) (int, error) {
	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	if keyBytes%8 > 0 {
		return 0, fmt.Errorf("ecdsa pubkey size error, curveBits %v", curveBits)
	}
	return keyBytes, nil
}

func rsCombinedBytes(rBytes, sBytes []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	keySize, err := ecdsakeyBytes(pubKey)
	if err != nil {
		return nil, fmt.Errorf("RSCombinedBytes: ecdsa key bytes error %v", err)
	}
	rsize := len(rBytes)
	ssize := len(sBytes)
	if rsize > keySize || ssize > keySize {
		return nil, fmt.Errorf("RSCombinedBytes: error. keySize %v, rSize %v, sSize %v", keySize, rsize, ssize)
	}

	// basically the size is 32 bytes. the r and s needs to be both left padded to two 32 bytes slice
	// into a single signature buffer
	buffer := make([]byte, keySize*2)
	startPos := keySize - rsize
	copy(buffer[startPos:], rBytes)
	startPos = keySize*2 - ssize
	copy(buffer[startPos:], sBytes)
	return buffer[:], nil
}

func sha256FromECPoint(X, Y *big.Int, pubKey *ecdsa.PublicKey) ([32]byte, error) {
	var sha [32]byte
	bytes, err := rsCombinedBytes(X.Bytes(), Y.Bytes(), pubKey)
	if err != nil {
		return sha, fmt.Errorf("error occurred while combining bytes for ECPoints: %v", err)
	}
	return sha256.Sum256(bytes), nil
}

func deriveSessionKey(X, Y *big.Int, publicKey *ecdsa.PublicKey) ([32]byte, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return [32]byte{}, fmt.Errorf("TPM open failed: %v", err)
	}
	defer rw.Close()
	p := tpm2.ECPoint{XRaw: X.Bytes(), YRaw: Y.Bytes()}

	//Recover the key, and decrypt the message
	z, err := tpm2.ECDHZGen(rw, tpmutil.Handle(*ecdhIndex), "", p)
	if err != nil {
		return [32]byte{}, fmt.Errorf("deriveSessionKey failed: %v", err)
	}
	return sha256FromECPoint(z.X(), z.Y(), publicKey)
}

func readDevicePubFromTPM() (crypto.PublicKey, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	deviceKey, _, _, err := tpm2.ReadPublic(rw, tpmutil.Handle(*certIndex))
	if err != nil {
		return nil, err
	}
	publicKey, err := deviceKey.Key()
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func readDevicePubFromFile(certFile string) (crypto.PublicKey, error) {
	//read public key from ecdh certificate
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("error in reading ecdh cert file: %v", err)
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("error in parsing ecdh cert file: %v", err)
		return nil, err
	}
	return cert.PublicKey, nil
}

func deriveEncryptDecryptKey() ([32]byte, error) {
	publicKey, err := readDevicePubFromTPM()
	if err != nil {
		return [32]byte{}, fmt.Errorf("error in readDevicePubFromTPM: %s", err)
	}
	eccPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return [32]byte{}, fmt.Errorf("Not an ECDH compatible key: %T", publicKey)
	}
	EncryptDecryptKey, err := deriveSessionKey(eccPublicKey.X, eccPublicKey.Y, eccPublicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("EncryptSecretWithDeviceKey failed with %v", err)
	}
	return EncryptDecryptKey, nil
}

func encryptDecryptUsingTpm(in []byte, encrypt bool) ([]byte, error) {
	key, err := deriveEncryptDecryptKey()
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	out := make([]byte, len(in))
	if encrypt {
		err = aesEncrypt(out, in, key[:], iv)
	} else {
		err = aesDecrypt(out, in, key[:], iv)
	}
	return out, err
}
