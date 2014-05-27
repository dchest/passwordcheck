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

// #include <limits.h>   // for INT_MAX
// #include "passwdqc.h"
import "C"
import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Error struct {
	reason *C.char
	desc   string
}

func (e *Error) Error() string {
	return e.desc
}

var errorsByReason = make(map[*C.char]*Error)

func newError(reason *C.char) *Error {
	e := &Error{reason, "passwordcheck: " + C.GoString(reason)}
	errorsByReason[reason] = e
	return e
}

var (
	ErrEmpty       = errors.New("empty password")
	ErrFailed      = newError(C.REASON_ERROR)       // check failed
	ErrSame        = newError(C.REASON_SAME)        // same as the old one
	ErrSimilar     = newError(C.REASON_SIMILAR)     // based on the old one
	ErrShort       = newError(C.REASON_SHORT)       // too short
	ErrLong        = newError(C.REASON_LONG)        // too long
	ErrSimpleShort = newError(C.REASON_SIMPLESHORT) // not enough different characters or classes for this length
	ErrSimple      = newError(C.REASON_SIMPLE)      // not enough different characters of classes
	ErrPersonal    = newError(C.REASON_PERSONAL)    // based on user name
	ErrWord        = newError(C.REASON_WORD)        // based on a directionary word and not a passphrase
	ErrSeq         = newError(C.REASON_SEQ)         // based on a common sequence of characters and not a passphrase
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
	// number of words (see the PassphraseWords option below).
	//
	// Min[3] and Min[4] are used for passwords consisting of characters
	// from three and four character classes, respectively.
	Min [5]int

	// Max is the maximum allowed password length.
	//
	// This can be used to prevent users from setting passwords that may be
	// too long for some system services.
	Max int

	// PassphraseWords is the number of words required for a passphrase.
	// Set to 0 to disable the support for user-chosen passphrases.
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

// Check checks that the new password complies with the policy and returns nil
// if it does, and Error if not.
//
// If old password or user name are not nil, the are also used for checking,
// for example, to make sure that the new password sufficiently differs from
// the old one.
func (p *Policy) Check(newPassword, oldPassword, username []byte) error {
	if newPassword == nil {
		return ErrEmpty
	}
	np := C.CString(string(newPassword))
	defer C.passwdqc_free(np)
	var op, u *C.char
	if oldPassword != nil {
		op = C.CString(string(oldPassword))
		defer C.passwdqc_free(op)
	}
	if username != nil {
		u = C.CString(string(username))
		defer C.passwdqc_free(u)
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

	reason := C.passwdqc_check(&params, np, op, u)
	if reason != nil {
		if err, ok := errorsByReason[reason]; ok {
			return err
		}
		return &Error{reason, C.GoString(reason)}
	}
	return nil
}

// ParsePolicy parses a string describing password policy.
// The format is similar to passwdqc, but a bit relaxed:
//
//  min=N0,N1,N2,N3,N4        default: min=disabled,24,11,8,7
//  max=N                     default: max=40
//  passphrase=N              default: passphrase=3
//  match=N                   default: match=4
//  similar=permit|deny       default: similar=deny
//
// Configuration items can be separated by a new line or by space,
// for example:
//
//  min=disabled,16,17,18,19 max=20 passphrase=21 match=22 similar=deny
//
// The order of items is not important.
// There must be no spaces or excess commas between min values.
// Items not present in the string are filled from DefaultPolicy.
func ParsePolicy(config string) (p *Policy, err error) {
	p = new(Policy)
	*p = *DefaultPolicy
	config = strings.Replace(config, "\r\n", " ", -1)
	config = strings.Replace(config, "\n", " ", -1)
	items := strings.Split(config, " ")
	for _, it := range items {
		nameValue := strings.SplitN(strings.TrimSpace(it), "=", 2)
		if len(nameValue) != 2 {
			return nil, fmt.Errorf("error parsing item: %q", it)
		}
		name, value := nameValue[0], nameValue[1]
		switch name {
		case "min":
			vals := strings.Split(value, ",")
			if len(vals) != 5 {
				return nil, fmt.Errorf("error parsing item: %q (expected 5 comma-separated values)", it)
			}
			for i, v := range vals {
				if v == "disabled" {
					p.Min[i] = Disabled
				} else {
					p.Min[i], err = strconv.Atoi(v)
					if err != nil {
						return nil, fmt.Errorf("error parsing item: %q (%s)", it, err)
					}
				}
			}
		case "max":
			p.Max, err = strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing item: %q (%s)", it, err)
			}
		case "passphrase":
			p.PassphraseWords, err = strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing item: %q (%s)", it, err)
			}
		case "match":
			p.MatchLength, err = strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing item: %q (%s)", it, err)
			}
		case "similar":
			switch value {
			case "deny":
				p.DenySimilar = true
			case "permit":
				p.DenySimilar = false
			default:
				return nil, fmt.Errorf("error parsing item: %q (unknown value %q)", it, value)
			}
		default:
			return nil, fmt.Errorf("unrecognized name: %q", name)
		}
	}
	return p, nil
}
