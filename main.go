// Quick and dirty tool, written in a span of a day,
// to make some machines happpy.

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/api/go/attest"
	progressbar "github.com/schollz/progressbar/v3"
	"google.golang.org/protobuf/proto"
)

const (
	tpmPropertyManufacturer tpm2.TPMProp = 0x105
	tpmPropertyVendorStr1   tpm2.TPMProp = 0x106
	tpmPropertyVendorStr2   tpm2.TPMProp = 0x107
	tpmPropertyFirmVer1     tpm2.TPMProp = 0x10b
	tpmPropertyFirmVer2     tpm2.TPMProp = 0x10c
)

// TpmPrivateKey is Custom implementation of crypto.PrivateKey interface
type TpmPrivateKey struct {
	PublicKey crypto.PublicKey
}

// Helper structure to pack ecdsa signature for ASN1 encoding
type ecdsaSignature struct {
	R, S *big.Int
}

const (
	TpmCredentialsFileName = "/config/tpm_credential"

	// TpmEKHdl is the well known TPM permanent handle for Endorsement key
	TpmEKHdl tpmutil.Handle = 0x81000001

	// TpmSRKHdl is the well known TPM permanent handle for Storage key
	TpmSRKHdl tpmutil.Handle = 0x81000002

	// TpmAKHdl is the well known TPM permanent handle for AIK key
	TpmAKHdl tpmutil.Handle = 0x81000003

	// TpmQuoteKeyHdl is the well known TPM permanent handle for PCR Quote signing key
	TpmQuoteKeyHdl tpmutil.Handle = 0x81000004

	//MaxPasswdLength is the max length allowed for a TPM password
	MaxPasswdLength = 7 //limit TPM password to this length

	ecdhCertFile = "/persist/certs/ecdh.cert.pem"
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

var (
	pcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}

	defaultEcdhKeyTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagNoDA | tpm2.FlagDecrypt |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagNoDA | tpm2.FlagDecrypt |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}

	defaultQuoteKeyTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagSign | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
		},
	}

	defaultAkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagSign | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	defaultSrkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	defaultEkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	myDevicePublicKey crypto.PublicKey
)

var logFilePath string

var (
	tpmPath           = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket)")
	tpmPass           = flag.String("tpm-pass", "", "TPM device password (if needed)")
	pubIndex          = flag.Uint("pub-index", 0, "Disk key public key NVRAM index")
	privIndex         = flag.Uint("priv-index", 0, "Disk Key private key NVRAM index")
	srkIndex          = flag.Uint("srk-index", 0, "SRK index")
	ecdhIndex         = flag.Uint("ecdh-index", 0, "ECDH index")
	devKeyIndex       = flag.Uint("dev-key-index", 0, "Device key index")
	certPath          = flag.String("cert-path", "", "Path to the device cert file")
	pcrHash           = flag.String("pcr-hash", "sha1", "PCR Hash algorithm (sha1, sha256)")
	pcrIndexes        = flag.String("pcr-index", "0, 1, 2, 3, 4, 6, 7, 8, 9, 13", "PCR Indexes to use for sealing and unsealing")
	exportPlain       = flag.Bool("export-plain", false, "Export the disk key in plain text")
	exportCloud       = flag.Bool("export-cloud", false, "Export the disk key in cloud encrypted form")
	importPlain       = flag.Bool("import-plain", false, "Import the disk key in plain text")
	importEncrypted   = flag.Bool("import-encrypted", false, "Import the disk key in encrypted form")
	reseal            = flag.Bool("reseal", false, "Reseal the disk key under new PCR indexes and hash algorithm")
	output            = flag.String("output", "", "Output file for the disk key")
	input             = flag.String("input", "", "Input file for the disk key")
	tpmInfo           = flag.Bool("tpm-info", false, "Print TPM information")
	testCount         = flag.Int("test-count", 10, "Number of times to run the test")
	clrTpm            = flag.Bool("clear-tpm", false, "Clear the TPM")
	initTpm           = flag.Bool("init-tpm", false, "Clear and initialize the TPM")
	testNewECDH       = flag.Bool("test-new-ecdh", false, "Generate a ECDH key and test TPM operations with it")
	testNewDevKey     = flag.Bool("test-new-dev-key", false, "Generate a device key and test TPM operations with it")
	testSysKeys       = flag.Bool("test-ecdh-dev-key", false, "Test ECDH operations on TPM with default device key and ECDH key")
	testNewECDHDevKey = flag.Bool("test-new-ecdh-dev-key", false, "Generated a new ECDH key and test TPM operations with it")
	removeECDH        = flag.Bool("remove-ecdh", false, "Remove the ECDH key from TPM")
	removeDevKey      = flag.Bool("remove-dev-key", false, "Remove the device key from TPM")
	genECDH           = flag.Bool("gen-ecdh", false, "Generate a new ECDH key")
	writeECDHCert     = flag.Bool("write-ecdh-cert", false, "Write the ECDH cert to disk")
	genDevKey         = flag.Bool("gen-dev-key", false, "Generate a new device key")
	checkCert         = flag.Bool("check-cert", false, "Check the device cert from disk against the TPM")
	logFile           = flag.String("log", "", "log file path")
)

func main() {
	initArgs()

	logFilePath = *logFile

	if *initTpm {
		log("[+] Initializing TPM\n")
		log("[+] Clearing TPM\n")

		err := clearTpm()
		if err != nil {
			log("error when clearing TPM: %v\n", err)
			os.Exit(1)
		}

		log("[+] Creating device key\n")
		err = createDeviceKey()
		if err != nil {
			log("error when creating device key: %v\n", err)
			os.Exit(1)
		}

		log("[+] Creating EK key\n")
		if err := createKey(TpmEKHdl, tpm2.HandleEndorsement, defaultEkTemplate); err != nil {
			log("Error in creating Endorsement key: %v ", err)
			os.Exit(1)
		}

		log("[+] Creating SRK key\n")
		if err := createKey(TpmSRKHdl, tpm2.HandleOwner, defaultSrkTemplate); err != nil {
			log("Error in creating SRK key: %v ", err)
			os.Exit(1)
		}

		log("[+] Creating AK key\n")
		if err := createKey(TpmAKHdl, tpm2.HandleOwner, defaultAkTemplate); err != nil {
			log("Error in creating Attestation key: %v ", err)
			os.Exit(1)
		}

		log("[+] Creating Quote key\n")
		if err := createKey(TpmQuoteKeyHdl, tpm2.HandleOwner, defaultQuoteKeyTemplate); err != nil {
			log("Error in creating Quote key: %v ", err)
			os.Exit(1)
		}

		log("[+] Creating ECDH key\n")
		if err := createKey(tpmutil.Handle(*ecdhIndex), tpm2.HandleOwner, defaultEcdhKeyTemplate); err != nil {
			log("Error in creating ECDH key: %v ", err)
			os.Exit(1)
		}

		log("[+] TPM initialized\n")
	}

	if *clrTpm {
		log("[+] Clearing TPM\n")
		err := clearTpm()
		if err != nil {
			log("error when clearing TPM: %v\n", err)
			os.Exit(1)
		}
		log("[+] TPM cleared\n")
	}

	if *removeECDH {
		log("[+] Removing ECDH key from TPM\n")
		err := removeKeyFromTpm(tpmutil.Handle(*ecdhIndex))
		if err != nil {
			log("error when removing key from TPM: %v\n", err)
			os.Exit(1)
		}
		log("[+] ECDH key removed from TPM\n")
	}

	if *removeDevKey {
		log("[+] Removing device key from TPM\n")
		err := removeKeyFromTpm(tpmutil.Handle(*devKeyIndex))
		if err != nil {
			log("error when removing key from TPM: %v\n", err)
			os.Exit(1)
		}
		log("[+] Device key removed from TPM\n")
	}

	if *genECDH {
		log("[+] Generating ECDH key\n")
		err := createKey(tpmutil.Handle(*ecdhIndex), tpm2.HandleOwner, defaultEcdhKeyTemplate)
		if err != nil {
			log("Error in creating ECDH key: %v\n", err)
			os.Exit(1)
		}
		log("[+] ECDH key generated\n")
	}

	if *writeECDHCert {
		if fileExists(ecdhCertFile) {
			log("[+] Removing current ECDH cert from disk...\n")
			err := os.Remove(ecdhCertFile)
			if err != nil {
				log("error when removing ECDH cert from disk: %v\n", err)
				os.Exit(1)
			}
		}

		log("[+] Writing ECDH cert to disk\n")
		err := createEcdhCertOnTpm()
		if err != nil {
			log("error when writing ECDH cert to disk: %v\n", err)
			os.Exit(1)
		}
		log("[+] ECDH cert written to disk\n")
	}

	if *genDevKey {
		log("[+] Generating device key\n")
		err := createDeviceKey()
		if err != nil {
			log("error when creating device key: %v\n", err)
			os.Exit(1)
		}
		log("[+] Device key generated\n")
	}

	if *testNewECDH {
		log("[+] Testing ECDH operations with a new ECDH key\n")
		err := createKey(tpmutil.Handle(*ecdhIndex), tpm2.HandleOwner, defaultEcdhKeyTemplate)
		if err != nil {
			log("Error in creating ECDH key: %v\n", err)
			os.Exit(1)
		}

		err = testECDHOperations()
		if err != nil {
			log("error when testing ECDH operations: %v\n", err)
			os.Exit(1)
		}

		return
	}

	if *testNewDevKey {
		log("[+] Testing ECDH operations with a new device key\n")
		err := createDeviceKey()
		if err != nil {
			log("error when creating device key: %v\n", err)
			os.Exit(1)
		}

		err = testECDHOperations()
		if err != nil {
			log("error when testing ECDH operations: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *testNewECDHDevKey {
		log("[+] Testing ECDH operations with a new ECDH key and device key\n")
		err := createKey(tpmutil.Handle(*ecdhIndex), tpm2.HandleOwner, defaultEcdhKeyTemplate)
		if err != nil {
			log("Error in creating ECDH key: %v\n", err)
			os.Exit(1)
		}

		err = createDeviceKey()
		if err != nil {
			log("error when creating device key: %v\n", err)
			os.Exit(1)
		}

		err = testECDHOperations()
		if err != nil {
			log("error when testing ECDH operations: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *testSysKeys {
		log("[+] Testing ECDH operations with default device key and ECDH key\n")
		err := testECDHOperations()
		if err != nil {
			log("error when testing ECDH operations: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *tpmInfo {
		info, err := fetchTpmHwInfo()
		if err != nil {
			log("error when fetching TPM info: %v\n", err)
			os.Exit(1)
		}

		log("[+] TPM Info: %s\n", info)
	}

	if *checkCert {
		tpmPublicKey, err := readDevicePubFromTPM()
		if err != nil {
			log("error when reading DevicePub from TPM: %v\n", err)
			os.Exit(1)
		}

		filePublicKey, err := readDevicePubFromFile(*certPath)
		if err != nil {
			log("error when reading DevicePub from file: %v\n", err)
			os.Exit(1)
		}

		if reflect.DeepEqual(tpmPublicKey, filePublicKey) {
			log("[+] Device cert matches TPM cert\n")
			return
		} else {
			log("[-] Device cert does not match TPM cert\n")
			os.Exit(1)
		}
	}

	if *exportPlain || *exportCloud {
		hashAlgo := tpm2.AlgSHA1
		if *pcrHash == "sha256" {
			hashAlgo = tpm2.AlgSHA256
		}

		*pcrIndexes = strings.TrimSpace(*pcrIndexes)
		pcrs, err := getPcrIndexes(strings.Split(*pcrIndexes, ","))
		if err != nil {
			log("error when parsing pcr-indexes: %v\n", err)
			os.Exit(1)
		}

		diskKey := make([]byte, 0)
		if *exportCloud || *exportPlain {
			pcrSel := tpm2.PCRSelection{Hash: hashAlgo, PCRs: pcrs}
			diskKey, err = getDiskKey(uint32(*privIndex), uint32(*pubIndex), uint32(*srkIndex), pcrSel)
			if err != nil {
				log("error when reading from the disk key: %v\n", err)
				os.Exit(1)
			}

			log("[+] Disk key available and exportable.\n")
		}

		// Export the disk key to the output file in plain text
		if *exportPlain && *output != "" {
			log("[+] Saving disk key to %s\n", *output)
			if err := os.WriteFile(string(*output), diskKey, 0644); err != nil {
				log("error when writing to the output file: %v\n", err)
				os.Exit(1)
			}
			log("[+] disk key saved.\n")
		}

		if *exportCloud && *output != "" {
			log("[+] Saving cloud-format encrypted disk key...\n")

			encryptedDiskKey, err := encryptDecryptUsingTpm(diskKey, true)
			if err != nil {
				log("error when encrypting disk key: %v\n", err)
				os.Exit(1)
			}

			if err := os.WriteFile(string(*output)+".raw", encryptedDiskKey, 0644); err != nil {
				log("error when writing raw formatted key to the output file: %v\n", err)
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
				log("error when marshaling AttestVolumeKeyData %v", err)
				os.Exit(1)
			}

			key := new(attest.AttestVolumeKey)
			key.KeyType = attest.AttestVolumeKeyType_ATTEST_VOLUME_KEY_TYPE_VSK
			key.Key = encryptedVaultKey

			volumeKey, err := proto.Marshal(key)
			if err != nil {
				log("error when marshaling AttestVolumeKey %v", err)
				os.Exit(1)
			}

			cloudDbFormat := fmt.Sprintf("0x%X", volumeKey)
			if err := os.WriteFile(string(*output)+".txt", []byte(cloudDbFormat), 0644); err != nil {
				log("error when writing cloud formatted key to the output file: %v\n", err)
				os.Exit(1)
			}

			log("[+] disk key saved.\n")
		}
	}

	if *reseal {
		log("[!] not implemented yet...\n")
		return
	}

	if *importPlain || *importEncrypted {
		log("[!] not implemented yet...\n")
		return
	}

	// TODO :
	// Import the disk key from the input file
	// Reseal the disk key under new PCR indexes and hash algorithm
}

func initArgs() {
	flag.Parse()

	if *checkCert {
		if *certPath == "" && *devKeyIndex == 0 {
			fmt.Fprintln(os.Stderr, "cert-path and cert-index must be specified for check-cert")
			os.Exit(1)
		}
	}

	if *genDevKey || *removeDevKey {
		if *devKeyIndex == 0 {
			fmt.Fprintln(os.Stderr, "cert-index must be specified")
			os.Exit(1)
		}
	}

	if *genECDH || *removeECDH {
		if *ecdhIndex == 0 {
			fmt.Fprintln(os.Stderr, "ecdh-index must be specified")
			os.Exit(1)
		}
	}

	if *testSysKeys || *testNewECDH || *testNewDevKey || *testNewECDHDevKey {
		if *ecdhIndex == 0 || *devKeyIndex == 0 {
			fmt.Fprintln(os.Stderr, "ecdh-index and cert-index must be specified")
			os.Exit(1)
		}
		return
	}

	if *exportPlain || *importPlain || *importEncrypted || *reseal || *exportCloud {

		if *pubIndex == 0 || *privIndex == 0 || *srkIndex == 0 {
			fmt.Fprintln(os.Stderr, "pub-index, priv-index and srk-index must be non-zero")
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

		if *exportCloud && *devKeyIndex == 0 {
			fmt.Fprintln(os.Stderr, "cert-index must be non-zero for export-cloud")
			os.Exit(1)
		}
	}
}

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
		return session, nil, fmt.Errorf("unable to get policy digest: %v", err)
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
		return nil, fmt.Errorf("load failed: %v", err)
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

	deviceKey, _, _, err := tpm2.ReadPublic(rw, tpmutil.Handle(*devKeyIndex))
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
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		log("error in reading ecdh cert file: %v", err)
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log("error in parsing ecdh cert file: %v", err)
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
		return [32]byte{}, fmt.Errorf("not an ECDH compatible key: %T", publicKey)
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

func testECDHOperations() error {
	data := "EKVPVCSJVWZXNWQGUXSFYYGCMAPPCFOJEKVPVCSJVWZXNWQGUXSFYYGCMAPPCFOJ"
	bar := progressbar.Default(int64(*testCount))

	for i := 0; i < *testCount; i++ {
		out, err := encryptDecryptUsingTpm([]byte(data), true)
		if err != nil {
			return fmt.Errorf("error when encrypting: %v", err)
		}

		out, err = encryptDecryptUsingTpm(out, false)
		if err != nil {
			return fmt.Errorf("error when decrypting: %v", err)
		}

		if string(out) != data {
			return fmt.Errorf("encrypt/decrypt failed: %s", out)
		}

		bar.Add(1)
	}

	log("[+] ECDH test enc/dec passed.\n")
	return nil
}

func createKey(keyHandle, ownerHandle tpmutil.Handle, template tpm2.Public) error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	handle, _, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		*tpmPass,
		*tpmPass,
		template)
	if err != nil {
		return fmt.Errorf("create 0x%x failed: %s, do BIOS reset of TPM", keyHandle, err)
	}

	_ = tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner,
		keyHandle,
		keyHandle)

	if err := tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner, handle,
		keyHandle); err != nil {
		return fmt.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
	}

	return nil
}

func readOwnerCrdl() (string, error) {
	tpmOwnerPasswdBytes, err := os.ReadFile(TpmCredentialsFileName)
	if err != nil {
		return "", err
	}
	tpmOwnerPasswd := string(tpmOwnerPasswdBytes)
	if len(tpmOwnerPasswd) > MaxPasswdLength {
		tpmOwnerPasswd = tpmOwnerPasswd[0:MaxPasswdLength]
	}
	return tpmOwnerPasswd, nil
}

func createDeviceKey() error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	tpmOwnerPasswd, err := readOwnerCrdl()
	if err != nil {
		return fmt.Errorf("reading owner credential failed: %v", err)
	}

	// No previous key, create new one
	// We later retrieve the public key from the handle to create the cert.
	signerHandle, _, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		*tpmPass,
		tpmOwnerPasswd,
		defaultKeyParams)

	if err != nil {
		return fmt.Errorf("CreatePrimary failed: %s, do BIOS reset of TPM", err)
	}

	_ = tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner,
		tpmutil.Handle(*devKeyIndex),
		tpmutil.Handle(*devKeyIndex))

	if err := tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner, signerHandle,
		tpmutil.Handle(*devKeyIndex)); err != nil {
		return fmt.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
	}

	return nil
}

func clearTpm() error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return fmt.Errorf("error in opening TPM: %v", err)
	}
	defer rw.Close()

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	err = tpm2.Clear(rw, tpm2.HandleLockout, auth)
	if err != nil {
		return fmt.Errorf("error in clearing TPM: %v", err)
	}
	return nil
}

func removeKeyFromTpm(keyHandle tpmutil.Handle) error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	err = tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner,
		keyHandle,
		keyHandle)
	if err != nil {
		return fmt.Errorf("EvictControl failed: %v", err)
	}
	return nil
}

// Public implements crypto.PrivateKey interface
func (s TpmPrivateKey) Public() crypto.PublicKey {
	if myDevicePublicKey != nil {
		ecdsaPublicKey := myDevicePublicKey.(*ecdsa.PublicKey)
		return ecdsaPublicKey
	}
	clientCertBytes, err := os.ReadFile(*certPath)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(clientCertBytes)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	ecdsaPublicKey := cert.PublicKey.(*ecdsa.PublicKey)
	return ecdsaPublicKey
}

// Sign implements crypto.PrivateKey interface
func (s TpmPrivateKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	R, S, err := TpmSign(digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{R, S})
}

// create Ecdh Template using the deviceCert for lifetimes
// Use a CommonName to differentiate from the device cert itself
func createEcdhTemplate(deviceCert x509.Certificate) x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
			Organization: []string{"The Linux Foundation"},
			CommonName:   "Device ECDH certificate",
		},
		NotBefore: deviceCert.NotBefore,
		NotAfter:  deviceCert.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return template
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}

	return false
}

func createEcdhCertOnTpm() error {
	//Check if we already have the certificate
	if !fileExists(ecdhCertFile) {
		//Cert is not present, generate new one
		rw, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {
			return fmt.Errorf("error in opening TPM: %v", err)
		}
		defer rw.Close()

		deviceCertBytes, err := os.ReadFile(*certPath)
		if err != nil {
			return fmt.Errorf("error in reading device cert: %v", err)
		}

		block, _ := pem.Decode(deviceCertBytes)
		if block == nil {
			return fmt.Errorf("failed in PEM decoding of deviceCertBytes")
		}

		deviceCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("error in parsing device cert: %v", err)
		}

		ecdhKey, _, _, err := tpm2.ReadPublic(rw, tpmutil.Handle(*ecdhIndex))
		if err != nil {
			return fmt.Errorf("error in reading ECDH key from TPM: %v", err)
		}

		publicKey, err := ecdhKey.Key()
		if err != nil {
			return fmt.Errorf("error in getting ECDH public key: %v", err)
		}

		tpmPrivKey := TpmPrivateKey{}
		tpmPrivKey.PublicKey = tpmPrivKey.Public()
		template := createEcdhTemplate(*deviceCert)

		cert, err := x509.CreateCertificate(rand.Reader,
			&template, deviceCert, publicKey, tpmPrivKey)
		if err != nil {
			return fmt.Errorf("error in creating ECDH cert: %v", err)
		}

		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}

		certBytes := pem.EncodeToMemory(certBlock)
		if certBytes == nil {
			return fmt.Errorf("empty bytes after encoding to PEM")
		}

		err = os.WriteFile(ecdhCertFile, certBytes, 0644)
		if err != nil {
			return fmt.Errorf("error in writing ECDH cert to disk: %v", err)
		}

	}
	return nil
}

func TpmSign(digest []byte) (*big.Int, *big.Int, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, nil, err
	}
	defer rw.Close()

	tpmOwnerPasswd, err := readOwnerCrdl()
	if err != nil {
		return nil, nil, fmt.Errorf("fetching TPM credentials failed: %w", err)
	}

	//XXX This "32" should really come from Hash algo used.
	if len(digest) > 32 {
		digest = digest[:32]
	}

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}
	sig, err := tpm2.Sign(rw, tpmutil.Handle(*devKeyIndex),
		tpmOwnerPasswd, digest, nil, scheme)
	if err != nil {
		return nil, nil, fmt.Errorf("signing data using TPM failed: %w", err)
	}
	return sig.ECC.R, sig.ECC.S, nil
}

func log(format string, args ...interface{}) {
	log := fmt.Sprintf(format, args...)
	fmt.Println(log)

	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when opening log file: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.WriteString(log)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when writing to log file: %v\n", err)
			return
		}
	}
}
