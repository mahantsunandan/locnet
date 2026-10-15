package node

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// userToken logs a local account on without its password and returns a
// primary token for it, ready for CreateProcessAsUser.
//
// This is "Service for User" (S4U): a process holding SeTcbPrivilege — which
// locnetd has, running as LocalSystem — may ask the LSA for a token for any
// local account by name. No password is supplied, stored or needed, and the
// token carries no network credentials, so a job can use the machine as that
// user but cannot reach file shares elsewhere as them. Tailscale's SSH server
// gets its Windows sessions the same way.
//
// Until this existed, compute on Windows could only run jobs as SYSTEM, which
// hands every allowed peer complete control of the machine.
//
// A network logon is asked for rather than a batch one: it needs only the
// "access this computer from the network" right, which every user has by
// default, where batch needs "log on as a batch job", which ordinary users do
// not. It also means Windows applies UAC's remote filtering to an
// administrator, so an admin account gets its unelevated token.
func userToken(account string) (windows.Token, error) {
	user, domain, err := localAccount(account)
	if err != nil {
		return 0, err
	}

	name, err := lsaString("LocNet")
	if err != nil {
		return 0, err
	}
	var lsa windows.Handle
	var mode uint32
	if st := lsaRegisterLogonProcess(name, &lsa, &mode); st != 0 {
		return 0, fmt.Errorf("registering with the LSA (needs locnetd to run as SYSTEM): %w", st.Errno())
	}
	defer lsaDeregisterLogonProcess(lsa)

	pkgName, err := lsaString("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0")
	if err != nil {
		return 0, err
	}
	var pkg uint32
	if st := lsaLookupAuthenticationPackage(lsa, pkgName, &pkg); st != 0 {
		return 0, fmt.Errorf("finding the MSV1_0 package: %w", st.Errno())
	}

	auth := newS4ULogon(user, domain)

	var source tokenSource
	copy(source.SourceName[:], "LocNet")
	if err := allocateLocallyUniqueID(&source.SourceIdentifier); err != nil {
		return 0, fmt.Errorf("AllocateLocallyUniqueId: %w", err)
	}

	var (
		profile    uintptr
		profileLen uint32
		logonID    windows.LUID
		token      windows.Token
		quotas     quotaLimits
		sub        windows.NTStatus
	)
	st := lsaLogonUser(lsa, name, logonTypeNetwork, pkg,
		unsafe.Pointer(&auth[0]), uint32(len(auth)*8),
		&source, &profile, &profileLen, &logonID, &token, &quotas, &sub)
	if profile != 0 {
		lsaFreeReturnBuffer(profile)
	}
	if st != 0 {
		if sub != 0 {
			return 0, fmt.Errorf("logging on %s\\%s: %w (%w)", domain, user, st.Errno(), sub.Errno())
		}
		return 0, fmt.Errorf("logging on %s\\%s: %w", domain, user, st.Errno())
	}
	return token, nil
}

// localAccount splits and checks an account name, accepting "name",
// ".\name" and "COMPUTER\name".
//
// The domain is always made explicit. A bare name is looked up against the
// computer's own name first, so on a machine called WinPC-01 with a user
// called winpc-01, "winpc-01" alone resolves to the computer.
func localAccount(account string) (user, domain string, err error) {
	computer, err := windows.ComputerName()
	if err != nil {
		return "", "", err
	}
	user = account
	if d, u, ok := strings.Cut(account, `\`); ok {
		if d != "." && !strings.EqualFold(d, computer) {
			return "", "", fmt.Errorf("%q is a domain account; compute can run jobs only as a local account on this machine", account)
		}
		user = u
	}
	if user == "" {
		return "", "", fmt.Errorf("no account name in %q", account)
	}
	_, _, kind, err := windows.LookupSID("", computer+`\`+user)
	if err != nil {
		return "", "", fmt.Errorf("no local account %q on this machine", user)
	}
	if kind != windows.SidTypeUser {
		return "", "", fmt.Errorf("%q is not a user account", user)
	}
	return user, computer, nil
}

// ------------------------------------------------------------- LSA plumbing

const (
	logonTypeNetwork = 3  // SECURITY_LOGON_TYPE Network
	msv1_0S4ULogon   = 12 // MSV1_0_LOGON_SUBMIT_TYPE MsV1_0S4ULogon
)

// msv1_0S4ULogonHeader is MSV1_0_S4U_LOGON. Its two strings must live in the
// same allocation, after the header: the LSA copies the block into its own
// process and rebases pointers that fall inside it.
type msv1_0S4ULogonHeader struct {
	MessageType       uint32
	Flags             uint32
	UserPrincipalName windows.NTUnicodeString
	DomainName        windows.NTUnicodeString
}

// newS4ULogon lays out header, user and domain in one 8-byte-aligned block.
func newS4ULogon(user, domain string) []uint64 {
	u := windows.StringToUTF16(user)
	u = u[:len(u)-1]
	d := windows.StringToUTF16(domain)
	d = d[:len(d)-1]

	head := int(unsafe.Sizeof(msv1_0S4ULogonHeader{}))
	size := head + 2*len(u) + 2*len(d)
	block := make([]uint64, (size+7)/8)
	base := unsafe.Pointer(&block[0])

	h := (*msv1_0S4ULogonHeader)(base)
	h.MessageType = msv1_0S4ULogon
	place := func(dst *windows.NTUnicodeString, off int, s []uint16) {
		p := (*uint16)(unsafe.Add(base, off))
		copy(unsafe.Slice(p, len(s)), s)
		dst.Buffer = p
		dst.Length = uint16(2 * len(s))
		dst.MaximumLength = dst.Length
	}
	place(&h.UserPrincipalName, head, u)
	place(&h.DomainName, head+2*len(u), d)
	return block
}

type tokenSource struct {
	SourceName       [8]byte
	SourceIdentifier windows.LUID
}

type quotaLimits struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             int64
}

func lsaString(s string) (*windows.NTString, error) { return windows.NewNTString(s) }

var (
	secur32  = windows.NewLazySystemDLL("secur32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	userenv  = windows.NewLazySystemDLL("userenv.dll")

	procLsaRegisterLogonProcess        = secur32.NewProc("LsaRegisterLogonProcess")
	procLsaDeregisterLogonProcess      = secur32.NewProc("LsaDeregisterLogonProcess")
	procLsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaLogonUser                   = secur32.NewProc("LsaLogonUser")
	procLsaFreeReturnBuffer            = secur32.NewProc("LsaFreeReturnBuffer")
	procAllocateLocallyUniqueId        = advapi32.NewProc("AllocateLocallyUniqueId")
	procLoadUserProfileW               = userenv.NewProc("LoadUserProfileW")
	procUnloadUserProfile              = userenv.NewProc("UnloadUserProfile")
)

func lsaRegisterLogonProcess(name *windows.NTString, h *windows.Handle, mode *uint32) windows.NTStatus {
	r, _, _ := procLsaRegisterLogonProcess.Call(uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(h)), uintptr(unsafe.Pointer(mode)))
	return windows.NTStatus(r)
}

func lsaDeregisterLogonProcess(h windows.Handle) { procLsaDeregisterLogonProcess.Call(uintptr(h)) }

func lsaLookupAuthenticationPackage(h windows.Handle, name *windows.NTString, pkg *uint32) windows.NTStatus {
	r, _, _ := procLsaLookupAuthenticationPackage.Call(uintptr(h),
		uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(pkg)))
	return windows.NTStatus(r)
}

func lsaLogonUser(h windows.Handle, origin *windows.NTString, logonType, pkg uint32,
	auth unsafe.Pointer, authLen uint32, source *tokenSource, profile *uintptr,
	profileLen *uint32, logonID *windows.LUID, token *windows.Token, quotas *quotaLimits,
	sub *windows.NTStatus) windows.NTStatus {
	r, _, _ := procLsaLogonUser.Call(uintptr(h), uintptr(unsafe.Pointer(origin)),
		uintptr(logonType), uintptr(pkg), uintptr(auth), uintptr(authLen),
		0, // no extra local groups
		uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(profile)),
		uintptr(unsafe.Pointer(profileLen)), uintptr(unsafe.Pointer(logonID)),
		uintptr(unsafe.Pointer(token)), uintptr(unsafe.Pointer(quotas)),
		uintptr(unsafe.Pointer(sub)))
	return windows.NTStatus(r)
}

func lsaFreeReturnBuffer(p uintptr) { procLsaFreeReturnBuffer.Call(p) }

func allocateLocallyUniqueID(l *windows.LUID) error {
	r, _, err := procAllocateLocallyUniqueId.Call(uintptr(unsafe.Pointer(l)))
	if r == 0 {
		return err
	}
	return nil
}

// profileInfo is PROFILEINFOW.
type profileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

// loadUserProfile makes the account's registry hive available, which is where
// its own environment — a per-user PATH entry for Python, say — lives. If the
// user is logged in it is already loaded and this only takes a reference.
// The returned function gives the reference back.
func loadUserProfile(token windows.Token, user string) (func(), error) {
	name, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return nil, err
	}
	pi := profileInfo{Flags: 1 /* PI_NOUI */, UserName: name}
	pi.Size = uint32(unsafe.Sizeof(pi))
	r, _, callErr := procLoadUserProfileW.Call(uintptr(token), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return nil, callErr
	}
	return func() { procUnloadUserProfile.Call(uintptr(token), uintptr(pi.Profile)) }, nil
}

// unelevated returns the token an administrator gets at the desktop under
// UAC: same account, Administrators reduced to deny-only, admin privileges
// gone, medium integrity. It takes ownership of t.
//
// "Run as the user" should mean what the user gets when they log in, not
// what they get after clicking Yes on a UAC prompt. An S4U logon of an
// administrator can come back fully elevated — it did on the first machine
// this ran on, where UAC's filtering for non-interactive logons is off — and
// running every allowed peer's job with that would be SYSTEM in all but name.
//
// When Windows has split the token itself, its limited half is used. When it
// has not, the same filtering is applied here.
func unelevated(t windows.Token) (windows.Token, error) {
	if !t.IsElevated() {
		return t, nil
	}
	var kind, n uint32
	if err := windows.GetTokenInformation(t, windows.TokenElevationType,
		(*byte)(unsafe.Pointer(&kind)), 4, &n); err == nil && kind == tokenElevationTypeFull {
		// Called with SeTcbPrivilege, this is a primary token.
		if linked, err := t.GetLinkedToken(); err == nil {
			t.Close()
			return checkUnelevated(linked)
		}
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Close()
		return 0, err
	}
	disable := []windows.SIDAndAttributes{{Sid: admins}}
	var limited windows.Token
	r, _, callErr := procCreateRestrictedToken.Call(uintptr(t),
		disableMaxPrivilege|luaToken,
		uintptr(len(disable)), uintptr(unsafe.Pointer(&disable[0])),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&limited)))
	t.Close()
	if r == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", callErr)
	}

	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		limited.Close()
		return 0, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(limited, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		limited.Close()
		return 0, fmt.Errorf("lowering the token to medium integrity: %w", err)
	}
	if err := ownByUser(limited); err != nil {
		limited.Close()
		return 0, err
	}
	return checkUnelevated(limited)
}

// ownByUser makes what the token creates belong to the user, as UAC does for
// its own filtered tokens. An administrator's token names Administrators as
// owner and default grantee of new objects — and with that group now
// deny-only, the job was shut out of the window station created for it and
// died loading user32 with 0xC0000142, as if the desktop fix had not worked.
func ownByUser(t windows.Token) error {
	tu, err := t.GetTokenUser()
	if err != nil {
		return err
	}
	user := tu.User.Sid
	owner := struct{ Owner *windows.SID }{user}
	if err := windows.SetTokenInformation(t, windows.TokenOwner,
		(*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner))); err != nil {
		return fmt.Errorf("making the user the token's default owner: %w", err)
	}

	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	grantees := []*windows.SID{user, system}
	if groups, err := t.GetTokenGroups(); err == nil {
		for _, g := range groups.AllGroups() {
			if g.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
				grantees = append(grantees, g.Sid)
			}
		}
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, sid := range grantees {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	dacl := struct{ DefaultDacl *windows.ACL }{acl}
	if err := windows.SetTokenInformation(t, windows.TokenDefaultDacl,
		(*byte)(unsafe.Pointer(&dacl)), uint32(unsafe.Sizeof(dacl))); err != nil {
		return fmt.Errorf("setting the token's default access: %w", err)
	}
	return nil
}

// checkUnelevated is the proof: whatever route produced the token, it is not
// handed to a job while Windows still calls it elevated.
func checkUnelevated(t windows.Token) (windows.Token, error) {
	if t.IsElevated() {
		t.Close()
		return 0, fmt.Errorf("could not obtain an unelevated token")
	}
	return t, nil
}

const (
	tokenElevationTypeFull = 2
	disableMaxPrivilege    = 0x1
	luaToken               = 0x4
)

var procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
