// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Local patch: ChaCha20 on 32-bit ARM using NEON (selected at run time from
// HWCAP_NEON via golang.org/x/sys/cpu). Falls back to xorKeyStreamBlocksGeneric
// on CPUs without NEON.

//go:build gc && !purego

package chacha20

import "golang.org/x/sys/cpu"

const bufSize = blockSize

var useNEON = cpu.ARM.HasNEON

//go:noescape
func xorKeyStreamNEON(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter *uint32)

func (c *Cipher) xorKeyStreamBlocks(dst, src []byte) {
	if useNEON {
		xorKeyStreamNEON(dst, src, &c.key, &c.nonce, &c.counter)
	} else {
		c.xorKeyStreamBlocksGeneric(dst, src)
	}
}
