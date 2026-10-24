// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Local patch: Poly1305 on 32-bit ARM using ARMv7 UMULL/UMLAL and VFPv3
// register transfers. Selected at run time when HWCAP_VFPv3 is set.

//go:build gc && !purego

package poly1305

import "golang.org/x/sys/cpu"

var useARM = cpu.ARM.HasVFPv3

//go:noescape
func updateASM(state *macState, msg []byte)

func update(state *macState, msg []byte) {
	if useARM {
		updateASM(state, msg)
	} else {
		updateGeneric(state, msg)
	}
}

type mac struct{ macGeneric }

func (h *mac) Write(p []byte) (int, error) {
	nn := len(p)
	if h.offset > 0 {
		n := copy(h.buffer[h.offset:], p)
		if h.offset+n < TagSize {
			h.offset += n
			return nn, nil
		}
		p = p[n:]
		h.offset = 0
		update(&h.macState, h.buffer[:])
	}
	if n := len(p) - (len(p) % TagSize); n > 0 {
		update(&h.macState, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return nn, nil
}

func (h *mac) Sum(out *[16]byte) {
	state := h.macState
	if h.offset > 0 {
		update(&state, h.buffer[:h.offset])
	}
	finalize(out, &state.h, &state.s)
}
