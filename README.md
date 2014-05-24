passwordcheck
=============

[![Build Status](https://travis-ci.org/dchest/passwordcheck.png)](https://travis-ci.org/dchest/passwordcheck)

Go package passwordcheck is a password and passphrase strength checker based on
[passwdqc](http://www.openwall.com/passwdqc/).

Currently implemented via a CGO-binding to a passwdqc (modified to remove
dependency on pwd.h). In the future I'd like to translate it to pure Go.

## Installation

```
$ go get github.com/dchest/passwordcheck
```

## Documentation
	
 <http://godoc.org/github.com/dchest/passwordcheck>
