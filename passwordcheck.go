// Go code written in 2014 by Dmitry Chestnykh.
// See LICENSE file.
//
// Documentation for Policy based on text by Solar Designer, taken from
// http://www.openwall.com/passwdqc/README.shtml.

// Package passwordcheck is a password and passphrase strength checker based on
// passwdqc (http://www.openwall.com/passwdqc/).
//
// Currently implemented via a CGO-binding to a modified passwdqc.
package passwordcheck

// #include <stdlib.h>   // for free
// #include <limits.h>   // for INT_MAX
// #include "passwdqc.h"
import "C"
import (
	"errors"
	"unsafe"
)

// Policy describes a password strength policy.
type Policy struct {
	// Min declares the minimum allowed password lengths for different
	// kinds of passwords and passphrases.
	//
	// Constant Disabled can be used to disallow passwords of a given kind
	// regardless of their length. Each subsequent number is required to be
	// no larger than the preceding one.
	//
	// Min[0] is used for passwords consisting of characters from one
	// character class only. The character classes are: digits, lower-case
	// letters, upper-case letters, and other characters. There is also a
	// special class for non-ASCII characters, which could not be
	// classified, but are assumed to be non-digits.
	//
	// Min[1] is used for passwords consisting of characters from two
	// character classes that do not meet the requirements for a
	// passphrase.
	//
	// Min[2] is used for passphrases. Note that besides meeting this
	// length requirement, a passphrase must also consist of a sufficient
	// number of words (see the "passphrase" option below).
	//
	// Min[3] and Min[4] are used for passwords consisting of characters
	// from three and four character classes, respectively.
	Min [5]int

	// Max is the maximum allowed password length.
	//
	// This can be used to prevent users from setting passwords that may be
	// too long for some system services.
	Max int

	// PassphraseWords is the number of words required for a passphrase, or
	// 0 to disable the support for user-chosen passphrases.
	PassphraseWords int

	// MatchLength is the length of common substring required to conclude
	// that a password is at least partially based on information found in
	// a character string, or 0 to disable the substring search.
	//
	// Note that the password will not be rejected once a weak substring is
	// found; it will instead be subjected to the usual strength
	// requirements with the weak substring partially discounted.
	MatchLength int

	// DenySimilar indicates whether a new password is allowed to be
	// similar to the old one.
	//
	// The passwords are considered to be similar when there is a
	// sufficiently long common substring and the new password with the
	// substring partially discounted would be weak.
	DenySimilar bool
}

// Disabled provides a value for Policy's Min to disable a password kind.
var Disabled = C.INT_MAX

// DefaultPolicy is the default password strength policy.
var DefaultPolicy = &Policy{
	Min:             [5]int{Disabled, 24, 11, 8, 7},
	Max:             1024,
	PassphraseWords: 3,
	MatchLength:     4,
	DenySimilar:     true,
}

// Check checks that the new password complies with the policy.
//
// If old password and user name are not nil, the are also used for checking,
// for example, to make sure that the new password sufficiently differs from
// the old one.
func (p *Policy) Check(newPassword, oldPassword, username []byte) error {
	if newPassword == nil {
		return errors.New("passwordcheck: empty new password")
	}
	np := C.CString(string(newPassword))
	defer C.free(unsafe.Pointer(np))
	var op, u *C.char
	if oldPassword != nil {
		op = C.CString(string(oldPassword))
		defer C.free(unsafe.Pointer(op))
	}
	if username != nil {
		u = C.CString(string(username))
		defer C.free(unsafe.Pointer(u))
	}
	// Copy parameters.
	var params C.passwdqc_params_qc_t
	for i, v := range p.Min {
		params.min[i] = C.int(v)
	}
	params.max = C.int(p.Max)
	params.passphrase_words = C.int(p.PassphraseWords)
	params.match_length = C.int(p.MatchLength)
	if p.DenySimilar {
		params.similar_deny = 1
	} else {
		params.similar_deny = 0
	}

	result := C.passwdqc_check(&params, np, op, u)
	if result != nil {
		return errors.New("passwordcheck: " + C.GoString(result))
	}
	return nil
}
