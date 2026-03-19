package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	PCRIndexMaxCount = 15
	PCRIndexMax      = 15
	PCRIndexSRTM     = 0
	PCRIndexGPT      = 5
	PCRIndexOS       = 15

	PcrSelection  = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}
	EmptyPassword = ""

	TpmEKHdl             tpmutil.Handle = 0x81000001
	TpmSRKHdl            tpmutil.Handle = 0x81000002
	TpmSealedDiskPrivHdl tpmutil.Handle = 0x1800000
	TpmSealedDiskPubHdl  tpmutil.Handle = 0x1900000

	DefaultEkTemplate = tpm2.Public{
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

	DefaultSrkTemplate = tpm2.Public{
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
)

func CreateKey(TpmPath string, keyHandle, ownerHandle tpmutil.Handle, template tpm2.Public, overwrite bool) error {
	rw, err := tpm2.OpenTPM(TpmPath)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}
	defer rw.Close()

	if !overwrite {
		//don't overwrite if key already exists, and if the attributes match up
		pub, _, _, err := tpm2.ReadPublic(rw, keyHandle)
		if err == nil && pub.Attributes == template.Attributes {
			fmt.Printf("Attributes match up, not re-creating 0x%X\n", keyHandle)
			return nil
		} else if err == nil {
			//key is present, but attributes not matching
			fmt.Printf("Attribute mismatch, re-creating 0x%X\n", keyHandle)
		} else {
			//key is not present
			fmt.Printf("key is not present, re-creating 0x%X\n", keyHandle)
		}
	}
	handle, _, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		PcrSelection,
		EmptyPassword,
		EmptyPassword,
		template)
	if err != nil {
		return fmt.Errorf("create 0x%x failed: %s, do BIOS reset of TPM", keyHandle, err)
	}
	// This call tries to remove the old index if it exists,
	// so no harm if it fails.
	_ = tpm2.EvictControl(rw, EmptyPassword, tpm2.HandleOwner, keyHandle, keyHandle)
	if err := tpm2.EvictControl(rw, EmptyPassword, tpm2.HandleOwner, handle, keyHandle); err != nil {
		return fmt.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
	}

	return nil
}

// SealDiskKey seals key into TPM2.0, with provided PCRs
func SealDiskKey(tpmPath string, key []byte, pcrSel tpm2.PCRSelection) error {
	rw, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmSealedDiskPubHdl)

	tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmSealedDiskPrivHdl)

	session, policy, err := PolicyPCRSession(rw, pcrSel)
	if err != nil {
		return fmt.Errorf("PolicyPCRSession failed: %w", err)
	}

	//Don't need the handle, we need only the policy for sealing
	if err := tpm2.FlushContext(rw, session); err != nil {
		return fmt.Errorf("flushing session handle %v failed: %w", session, err)
	}

	priv, public, err := tpm2.Seal(rw, TpmSRKHdl, EmptyPassword, EmptyPassword, policy, key)
	if err != nil {
		return fmt.Errorf("sealing the disk key into TPM failed: %w", err)
	}

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		TpmSealedDiskPrivHdl,
		EmptyPassword,
		EmptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(priv)),
	); err != nil {
		return fmt.Errorf("NVDefineSpace %v failed: %w", TpmSealedDiskPrivHdl, err)
	}

	// Write the private data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmSealedDiskPrivHdl,
		EmptyPassword, priv, 0); err != nil {
		return fmt.Errorf("NVWrite %v failed: %w", TpmSealedDiskPrivHdl, err)
	}

	// Define space in NV storage
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		TpmSealedDiskPubHdl,
		EmptyPassword,
		EmptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(public)),
	); err != nil {
		return fmt.Errorf("NVDefineSpace %v failed: %w", TpmSealedDiskPubHdl, err)
	}
	// Write the public data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmSealedDiskPubHdl,
		EmptyPassword, public, 0); err != nil {
		return fmt.Errorf("NVWrite %v failed: %w", TpmSealedDiskPubHdl, err)
	}

	return nil
}

func UnsealDiskKey(tpmPath string, pcrSel tpm2.PCRSelection) ([]byte, error) {
	rw, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	priv, err := tpm2.NVReadEx(rw, TpmSealedDiskPrivHdl,
		tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %w", TpmSealedDiskPrivHdl, err)
	}
	// Read all of the data with NVReadEx
	pub, err := tpm2.NVReadEx(rw, TpmSealedDiskPubHdl,
		tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %w", TpmSealedDiskPubHdl, err)
	}

	sealedObjHandle, _, err := tpm2.Load(rw, TpmSRKHdl, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("loading the disk key into TPM failed: %w", err)
	}
	defer tpm2.FlushContext(rw, sealedObjHandle)

	session, _, err := PolicyPCRSession(rw, pcrSel)
	if err != nil {
		return nil, fmt.Errorf("PolicyPCRSession failed: %w", err)
	}
	defer tpm2.FlushContext(rw, session)

	key, err := tpm2.UnsealWithSession(rw, session, sealedObjHandle, EmptyPassword)
	if err != nil {
		return nil, fmt.Errorf("UnsealWithSession failed: %w", err)
	}
	return key, nil
}

// PolicyPCRSession prepares TPM2 Auth Policy session, with PCR as the policy
func PolicyPCRSession(rw io.ReadWriteCloser, pcrSel tpm2.PCRSelection) (tpmutil.Handle, []byte, error) {
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
		return tpm2.HandleNull, nil, fmt.Errorf("StartAuthSession failed: %w", err)
	}
	defer func() {
		if session != tpm2.HandleNull && err != nil {
			tpm2.FlushContext(rw, session)
		}
	}()

	if err = tpm2.PolicyPCR(rw, session, nil, pcrSel); err != nil {
		return session, nil, fmt.Errorf("PolicyPCR failed: %w", err)
	}

	policy, err := tpm2.PolicyGetDigest(rw, session)
	if err != nil {
		return session, nil, fmt.Errorf("PolicyGetDigest failed: %w", err)
	}
	return session, policy, nil
}

func getAuthDigest(tpmPath string, handle tpmutil.Handle) ([]byte, error) {
	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	nvData, err := tpm2.NVReadEx(rwc, handle, tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		return nil, err
	}

	pubKey, err := tpm2.DecodePublic(nvData)
	if err != nil {
		return nil, err
	}

	return pubKey.AuthPolicy, nil
}

const TPM_CC_PolicyPCR tpmutil.Command = 0x0000017F

// ComputeAuthDigest replicates the TPM's PolicyPCR digest calculation.
//
// The formula for the policy digest update is:
// newPolicyDigest = Hash( oldPolicyDigest || TPM_CC_PolicyPCR || pcrs || digestTPM )
//
// Parameters:
//   - oldPolicyDigest: The current policy digest. For a new policy session, this is 32 bytes of zeros.
//   - TPM_CC_PolicyPCR: The command code for PolicyPCR (0x0000017F), encoded as a 32-bit big-endian integer.
//   - pcrs: The TPML_PCR_SELECTION structure indicating which PCRs are selected.
//     It contains [Count (uint32) | HashAlg (uint16) | SizeOfSelect (uint8) | PcrSelect (bitmap)]
//   - digestTPM: The hash of the values of the selected PCRs.
//
// Refrence:
//   - TPM 2.0, David Wooten - Microsoft Corp, Section "Authorization",
//   - TCG Trusted Attestation Protocol (TAP) Information Model
//     for TPM Families 1.2 and 2.0 and DICE Family 1.0,
//     section 4.4 "Attestation of TPM 2.0 Signing Key used for Implicit Attestation"
func ComputeAuthDigest(pcrValues map[int][]byte, pcrIndices []int) ([]byte, error) {
	// Prepare "digestTPM", this is the hash of the concatenation of all selected PCR values.
	sortedIndices := make([]int, len(pcrIndices))
	copy(sortedIndices, pcrIndices)
	sort.Ints(sortedIndices)
	pcrValueHash := sha256.New()
	for _, idx := range sortedIndices {
		val, ok := pcrValues[idx]
		if !ok {
			return nil, fmt.Errorf("missing PCR value for index %d", idx)
		}
		pcrValueHash.Write(val)
	}
	pcrsDigest := pcrValueHash.Sum(nil)
	digestTPM := new(bytes.Buffer)
	digestTPM.Write(pcrsDigest)

	// Prepare "pcrs" (TPML_PCR_SELECTION), This structure describes the PCR selection.
	// We set the size of select bitmap to 3 bytes, which covers PCRs 0-23.
	sizeOfSelect := uint8(3)
	pcrs := new(bytes.Buffer)
	// TPML_PCR_SELECTION.Count: Number of selection structures (1 since we select only SHA256)
	binary.Write(pcrs, binary.BigEndian, uint32(1))
	// TPMS_PCR_SELECTION.HashAlg: The hash algorithm of the PCR bank
	binary.Write(pcrs, binary.BigEndian, uint16(tpm2.AlgSHA256))
	// TPMS_PCR_SELECTION.SizeOfSelect: Size of the bitmap in bytes
	binary.Write(pcrs, binary.BigEndian, sizeOfSelect)

	// The bitmap indicates which PCRs are active, e.g. for PCR 0, bit 0 of byte 0 is set.
	bitmap := make([]byte, sizeOfSelect)
	for _, pcr := range sortedIndices {
		bytePos := pcr / 8
		// This should never happen, just in case
		if int(bytePos) >= int(sizeOfSelect) {
			return nil, fmt.Errorf("PCR index %d out of range for selection size %d", pcr, sizeOfSelect)
		}
		bitPos := pcr % 8
		bitmap[bytePos] |= (1 << bitPos)
	}
	pcrs.Write(bitmap)

	// Prepare "oldPolicyDigest", the initial policy digest is all zeros.
	oldPolicyDigest := make([]byte, 32)

	// Final Calculation : Hash( oldPolicyDigest || TPM_CC_PolicyPCR || pcrs || digestTPM )
	h := sha256.New()
	h.Write(oldPolicyDigest)
	binary.Write(h, binary.BigEndian, uint32(TPM_CC_PolicyPCR))
	h.Write(pcrs.Bytes())
	h.Write(digestTPM.Bytes())

	return h.Sum(nil), nil
}

func bruteForcePCRs(tpmPath string, targetDigest []byte) error {
	// The specific list of PCR indexes you provided
	candidates := []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	n := len(candidates)

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return err
	}
	defer rwc.Close()

	fmt.Println("Prefetching PCR values from TPM...")
	pcrValues := make(map[int][]byte)
	for _, pdx := range candidates {
		val, err := tpm2.ReadPCR(rwc, pdx, tpm2.AlgSHA256)
		if err != nil {
			return fmt.Errorf("failed to read PCR %d: %v", pdx, err)
		}
		pcrValues[pdx] = val
	}

	fmt.Println("Starting brute-fore on PCR subsets (offline calculation)...")
	// There are 2^n combinations.
	// We iterate from 0 to 2^n - 1.
	// 1 << n is equivalent to 2^n.
	limit := 1 << n

	for i := 0; i < limit; i++ {
		var subset []int

		// Check each bit position to see if the corresponding PCR
		// should be included in this specific subset.
		for j := 0; j < n; j++ {
			// If the j-th bit of i is set (1), include candidates[j]
			if i&(1<<j) != 0 {
				subset = append(subset, candidates[j])
			}
		}

		// Check this combination using offline calculation
		digest, err := ComputeAuthDigest(pcrValues, subset)
		if err != nil {
			fmt.Printf("Error computing digest for subset %v: %v\n", subset, err)
			continue
		}

		if bytes.Equal(digest, targetDigest) {
			fmt.Println("Found correct combination:", subset)
			return nil
		}

		if i%1000 == 0 {
			fmt.Printf("Checked %d/%d combinations...\r", i, limit)
		}
	}

	fmt.Println("\nNo matching combination found.")
	return fmt.Errorf("no matching combination found")
}

func verifyComputeAuthDigest(tpmPath string) {
	fmt.Println("\n--- Verifying ComputeAuthDigest with multiple scenarios ---")

	func() {
		rwc, err := tpm2.OpenTPM(tpmPath)
		if err != nil {
			fmt.Printf("Failed to open TPM: %v\n", err)
			return
		}
		defer rwc.Close()

		fmt.Println("Current PCR Values (SHA256):")
		for i := 0; i < 24; i++ {
			val, err := tpm2.ReadPCR(rwc, i, tpm2.AlgSHA256)
			if err == nil {
				fmt.Printf("  PCR %2d: %x\n", i, val)
			}
		}
	}()

	scenarios := [][]int{
		{0},
		{7},
		{0, 7},
		{0, 7, 14},
		{1, 2, 3, 4, 5},
	}

	for i, pcrs := range scenarios {
		fmt.Printf("\nScenario %d: PCRs %v\n", i+1, pcrs)
		pcrSel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrs}

		// 1. Seal Key (Generates Policy on TPM)
		// We use SealDiskKey as a helper to set up the policy session, seal an object,
		// and save the public area (which contains the policy digest) to NV so we can read it.
		if err := SealDiskKey(tpmPath, []byte("ignored"), pcrSel); err != nil {
			fmt.Printf("  Failed to seal key: %v\n", err)
			continue
		}

		// 2. Get TPM generated Digest from the sealed object's public area
		tpmDigest, err := getAuthDigest(tpmPath, TpmSealedDiskPubHdl)
		if err != nil {
			fmt.Printf("  Failed to get auth digest: %v\n", err)
			continue
		}

		// 3. Compute Digest Offline
		// We need to fetch the current PCR values from the TPM to perform the calculation.
		rwc, err := tpm2.OpenTPM(tpmPath)
		if err != nil {
			fmt.Printf("  Failed to open TPM: %v\n", err)
			continue
		}

		pcrValues := make(map[int][]byte)
		readErr := false
		for _, idx := range pcrs {
			val, err := tpm2.ReadPCR(rwc, idx, tpm2.AlgSHA256)
			if err != nil {
				fmt.Printf("  Failed to read PCR %d: %v\n", idx, err)
				readErr = true
				break
			}
			pcrValues[idx] = val
		}
		rwc.Close()
		if readErr {
			continue
		}

		computedDigest, err := ComputeAuthDigest(pcrValues, pcrs)
		if err != nil {
			fmt.Printf("  Failed to compute digest: %v\n", err)
			continue
		}

		// 4. Compare
		fmt.Printf("  TPM Digest:      %x\n", tpmDigest)
		fmt.Printf("  Computed Digest: %x\n", computedDigest)

		if bytes.Equal(tpmDigest, computedDigest) {
			fmt.Println("  RESULT: MATCH")
		} else {
			fmt.Println("  RESULT: MISMATCH")
		}
	}
}

func main() {
	TpmDevicePath := "/dev/tpmrm0"

	auth, err := getAuthDigest(TpmDevicePath, TpmSealedDiskPubHdl)
	if err != nil {
		fmt.Printf("error getting auth digest: %v\n", err)
		return
	}
	fmt.Printf("Target Auth Digest: %x\n", auth)

	if err := bruteForcePCRs(TpmDevicePath, auth); err != nil {
		fmt.Printf("Brute force failed: %v\n", err)
	}
}
