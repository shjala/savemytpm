### EVE Volume Key Recovery Tool
This is tool made to conveniently extract [EVE](https://github.com/lf-edge/eve/) volume encryption key from TPM. It can extract keys both in plain text format and in an encrypted format suited for inserting into a cloud controller database like [Adam](https://github.com/lf-edge/adam) or [Zedcloud](https://zededa.com/). Note the that tool can only extract keys from TPM if the device state (current PCR values) match the original state where key was seald.

#### Usage
The tool compiles for Alpine envirnment (EVE's base). The `recover-tpm.sh` downloads the arch specific binary and comes with predefined values to extract keys from specific versions of EVE, but the main tool is flexiable in its usage:

```text
$ ./savemytpm --help
Usage of ./savemytpm:
  -cert-index uint
    	Device Cert index
  -cert-path string
    	Path to the device cert file
  -check-cert
    	Check the device cert from disk against the TPM
  -ecdh-index uint
    	ECDH index
  -export-cloud
    	Export the disk key in cloud encrypted form
  -export-encrypted
    	Export the disk key in encrypted form
  -export-plain
    	Export the disk key in plain text
  -import-encrypted
    	Import the disk key in encrypted form
  -import-plain
    	Import the disk key in plain text
  -input string
    	Input file for the disk key
  -output string
    	Output file for the disk key
  -pcr-hash string
    	PCR Hash algorithm (sha1, sha256) (default "sha1")
  -pcr-index string
    	PCR Indexes to use for sealing and unsealing (default "0, 1, 2, 3, 4, 6, 7, 8, 9, 13")
  -priv-index uint
    	Disk Key private key NVRAM index
  -pub-index uint
    	Disk key public key NVRAM index
  -reseal
    	Reseal the disk key under new PCR indexes and hash algorithm
  -srk-index uint
    	SRK index
  -tpm-pass string
    	TPM device password (if needed)
  -tpm-path string
    	Path to the TPM device (character device or a Unix socket) (default "/dev/tpm0")
```