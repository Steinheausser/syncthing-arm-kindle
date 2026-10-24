// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Local patch (hwsha): SHA-256 on 32-bit ARM using the ARMv8 AArch32 crypto
// extension, selected at run time from HWCAP2_SHA2. Falls back to the
// generic Go code on CPUs without it (e.g. plain ARMv7).

//go:build !purego

package sha256

import (
	"crypto/internal/fips140deps/cpu"
	"crypto/internal/impl"
)

var useSHA2 = cpu.ARMHasSHA2

func init() {
	impl.Register("sha256", "Armv8.0-AArch32", &useSHA2)
}

//go:noescape
func blockSHA2(dig *Digest, p []byte)

func block(dig *Digest, p []byte) {
	if useSHA2 {
		blockSHA2(dig, p)
	} else {
		blockGeneric(dig, p)
	}
}
