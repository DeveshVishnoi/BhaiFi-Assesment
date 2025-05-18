// internal/signature/verifier.go
package signature

import (
	"crypto/x509"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IMAGE_DOS_SIGNATURE            = 0x5A4D     // "MZ"
	IMAGE_NT_SIGNATURE             = 0x00004550 // "PE\0\0"
	IMAGE_DIRECTORY_ENTRY_SECURITY = 4          // Certificate table index
)

type Verifier struct {
	trustedRoots *x509.CertPool
}

func NewVerifier() (*Verifier, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %w", err)
	}
	return &Verifier{trustedRoots: pool}, nil
}

const (
	WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
	WTD_REVOKE_NONE                   = 0
	WTD_CHOICE_FILE                   = 1
	WTD_STATEACTION_VERIFY            = 1
	WTD_STATEACTION_CLOSE             = 2
	WTD_UI_NONE                       = 2
	TRUST_E_NOSIGNATURE               = 0x800B0100
	TRUST_E_EXPIRED                   = 0x800B0101
	TRUST_E_PROVIDER_UNKNOWN          = 0x800B0001
	TRUST_E_BAD_DIGEST                = 0x80096010
	TRUST_E_SUBJECT_NOT_TRUSTED       = 0x800B0004
)

type WINTRUST_FILE_INFO struct {
	StructSize   uint32
	FilePath     *uint16
	FileHandle   syscall.Handle
	KnownSubject *windows.GUID
}

type WINTRUST_DATA struct {
	StructSize         uint32
	PolicyCallbackData uintptr
	SIPClientData      uintptr
	UIChoice           uint32
	RevocationChecks   uint32
	UnionChoice        uint32
	FileInfo           uintptr
	StateAction        uint32
	StateData          syscall.Handle
	URLReference       *uint16
	ProvFlags          uint32
	UIContext          uint32
	SignatureSettings  uintptr
}

func isBinarySigned(filePath string) (bool, error) {
	filePathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to convert file path: %v", err)
	}

	fileInfo := WINTRUST_FILE_INFO{
		StructSize: uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		FilePath:   filePathPtr,
	}

	var wintrustData WINTRUST_DATA
	wintrustData.StructSize = uint32(unsafe.Sizeof(wintrustData))
	wintrustData.UIChoice = WTD_UI_NONE
	wintrustData.RevocationChecks = WTD_REVOKE_NONE
	wintrustData.UnionChoice = WTD_CHOICE_FILE
	wintrustData.FileInfo = uintptr(unsafe.Pointer(&fileInfo))
	wintrustData.StateAction = WTD_STATEACTION_VERIFY
	wintrustData.ProvFlags = 0 // Default flags

	wintrust := windows.MustLoadDLL("wintrust.dll")
	winVerifyTrust := wintrust.MustFindProc("WinVerifyTrust")

	guidAction, err := windows.GUIDFromString(WINTRUST_ACTION_GENERIC_VERIFY_V2)
	if err != nil {
		return false, fmt.Errorf("failed to parse GUID: %v", err)
	}

	r1, _, err := winVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&guidAction)),
		uintptr(unsafe.Pointer(&wintrustData)),
	)

	wintrustData.StateAction = WTD_STATEACTION_CLOSE
	winVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&guidAction)),
		uintptr(unsafe.Pointer(&wintrustData)),
	)

	fmt.Printf("WinVerifyTrust for %s returned code: 0x%x (%d)\n", filePath, r1, r1)

	if r1 == 0 {
		return true, nil
	}
	switch uint32(r1) {
	case TRUST_E_NOSIGNATURE:
		return false, nil
	case TRUST_E_EXPIRED:
		return true, fmt.Errorf("signature is expired")
	case TRUST_E_PROVIDER_UNKNOWN:
		return false, fmt.Errorf("unknown trust provider")
	case TRUST_E_BAD_DIGEST:
		return true, fmt.Errorf("signature digest is invalid")
	case TRUST_E_SUBJECT_NOT_TRUSTED:
		return true, fmt.Errorf("signature is not trusted")
	default:
		return false, fmt.Errorf("WinVerifyTrust failed with code 0x%x: %v", r1, err)
	}
}

func (v *Verifier) Verify(filePath string) (bool, error) {
	isSigned, err := isBinarySigned(filePath)
	if err != nil {
		fmt.Printf("Error checking signature: %v\n", err)
		return false, err
	}
	if isSigned {
		return true, nil
	}
	return false, nil

}
