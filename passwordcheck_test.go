// Go code written in 2014 by Dmitry Chestnykh.
// See LICENSE file.

package passwordcheck

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"testing"
)

func TestCheck(t *testing.T) {
	p0 := "password1"
	p1 := "password2"
	u := "brewery"
	err := DefaultPolicy.Check([]byte(p0), []byte(p1), []byte(u))
	if err == nil {
		t.Error("error expected")
	}
}

func TestCheckNil(t *testing.T) {
	err := DefaultPolicy.Check(nil, nil, nil)
	if err == nil {
		t.Error("error expected")
	}
	err = DefaultPolicy.Check([]byte("dw1lIojbTBrq/gii1MzfZVL83wlIdAe/2v1xsQmybHU"), nil, nil)
	if err != nil {
		t.Errorf("no error expected, got %s", err)
	}
}

func TestDisabled(t *testing.T) {
	pass := []byte("pwrjysrgylwwajk")
	pol := *DefaultPolicy
	pol.Min[0] = Disabled
	err := pol.Check(pass, nil, nil)
	if err == nil {
		t.Error("error expected")
	}
	pol.Min[0] = len(pass)
	err = pol.Check(pass, nil, nil)
	if err != nil {
		t.Errorf("no error expected, got %s", err)
	}
	pol.PassphraseWords = 3
	err = pol.Check([]byte("correct horse whatever"), nil, nil)
	if err != nil {
		t.Errorf("no error expected, got %s", err)
	}
}

func TestErrReturn(t *testing.T) {
	err := DefaultPolicy.Check([]byte("pass"), nil, nil)
	if err != ErrShort {
		t.Errorf("expected ErrShort, got %v", err)
	}
	err = DefaultPolicy.Check([]byte("JJJRedRyIdHCJQ131"), []byte("131QJCHdIyRdeRJJJ"), nil)
	if err != ErrSimilar {
		t.Errorf("expected ErrSimilar, got %v", err)
	}
}

func checkPasswordsFromFile(t *testing.T, filename string) {
	fmt.Printf("[INFO] Checking common passwords from %s\n", filename)
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	defer z.Close()
	scanner := bufio.NewScanner(z)
	numRead := 0
	numRejected := 0
	rejections := make(map[error]int)
	for scanner.Scan() {
		pw := scanner.Text()
		if r := DefaultPolicy.Check([]byte(pw), nil, nil); r != nil {
			rejections[r]++
			numRejected++
		} else {
			fmt.Printf("[INFO] Accepted password: %q\n", pw)
		}
		numRead++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for k, v := range rejections {
		fmt.Printf("[INFO] %d passwords: %s\n", v, k)
	}
	fmt.Printf("[INFO] Rejected %d of %d passwords\n", numRejected, numRead)
}

func TestCommonPasswords(t *testing.T) {
	checkPasswordsFromFile(t, "testdata/passwords.txt.gz")
}
