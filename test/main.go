// Correctness and throughput test for the ARMv8/NEON crypto overlay:
//   - crypto/internal/fips140/sha256 (blockSHA2 vs blockGeneric)
//   - vendor/golang.org/x/crypto/chacha20 (xorKeyStreamNEON vs xorKeyStreamBlocksGeneric)
//   - vendor/golang.org/x/crypto/internal/poly1305 (updateASM vs updateGeneric)
//   - vendor/golang.org/x/crypto/chacha20poly1305 (AEAD Seal/Open on 16 KiB TLS records)
//
// Build with -overlay=overlay.json and -ldflags=-checklinkname=0.
package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	_ "crypto/tls"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
	_ "unsafe"
)

//go:linkname useSHA2 crypto/internal/fips140/sha256.useSHA2
var useSHA2 bool

//go:linkname useNEON vendor/golang.org/x/crypto/chacha20.useNEON
var useNEON bool

//go:linkname useARM vendor/golang.org/x/crypto/internal/poly1305.useARM
var useARM bool

//go:linkname newAEAD vendor/golang.org/x/crypto/chacha20poly1305.New
func newAEAD(key []byte) (cipher.AEAD, error)

//go:linkname xorKeyStreamNEON vendor/golang.org/x/crypto/chacha20.xorKeyStreamNEON
func xorKeyStreamNEON(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter *uint32)

//go:linkname polySum vendor/golang.org/x/crypto/internal/poly1305.Sum
func polySum(out *[16]byte, m []byte, key *[32]byte)

type polyMacState struct {
	h [3]uint64
	r [2]uint64
	s [2]uint64
}

//go:linkname polyInit vendor/golang.org/x/crypto/internal/poly1305.initialize
func polyInit(key *[32]byte, m *polyMacState)

//go:linkname polyUpdateASM vendor/golang.org/x/crypto/internal/poly1305.updateASM
func polyUpdateASM(state *polyMacState, msg []byte)

//go:linkname polyUpdateGeneric vendor/golang.org/x/crypto/internal/poly1305.updateGeneric
func polyUpdateGeneric(state *polyMacState, msg []byte)

//go:linkname polyFinalize vendor/golang.org/x/crypto/internal/poly1305.finalize
func polyFinalize(out *[16]byte, h *[3]uint64, s *[2]uint64)

var (
	availSHA2 bool
	availNEON bool
	availARM  bool
	failures  int
)

func failf(format string, args ...any) {
	failures++
	if failures <= 25 {
		fmt.Printf("FAIL: "+format+"\n", args...)
	}
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func testSHA256(buf []byte, rng *rand.Rand) {
	vectors := []struct{ in, out string }{
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
		{strings.Repeat("a", 1000000), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}
	for _, v := range vectors {
		useSHA2 = availSHA2
		got := sha256.Sum256([]byte(v.in))
		if hex.EncodeToString(got[:]) != v.out {
			failf("sha256 NIST %d", len(v.in))
		}
	}
	for l := 0; l <= 300; l++ {
		for off := 0; off < 4; off++ {
			useSHA2 = false
			want := sha256.Sum256(buf[off : off+l])
			useSHA2 = availSHA2
			got := sha256.Sum256(buf[off : off+l])
			if got != want {
				failf("sha256 len=%d off=%d", l, off)
			}
		}
	}
	for i := 0; i < 100; i++ {
		l := rng.Intn(256 << 10)
		off := rng.Intn(16)
		useSHA2 = false
		want := sha256.Sum256(buf[off : off+l])
		useSHA2 = availSHA2
		got := sha256.Sum256(buf[off : off+l])
		if got != want {
			failf("sha256 rand len=%d", l)
		}
	}
	fmt.Println("sha256 correctness: ok")
}

func testPoly1305(buf []byte, rng *rand.Rand) {
	// RFC 8439 Section 2.5.2 test vector.
	rfcKey := unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	rfcMsg := []byte("Cryptographic Forum Research Group")
	rfcWant := unhex("a8061dc1305136c6c22b8baf0c0127a9")
	var k32 [32]byte
	copy(k32[:], rfcKey)
	var tag [16]byte
	useARM = availARM
	polySum(&tag, rfcMsg, &k32)
	if !bytes.Equal(tag[:], rfcWant) {
		failf("poly1305 RFC 8439 got=%x want=%x", tag, rfcWant)
	}

	// Extremal keys & messages (all-0xff, all-0x00, alternating) to stress carries.
	specialKeys := [][32]byte{
		{},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	rng.Read(k32[:])
	specialKeys = append(specialKeys, k32)

	ffBuf := bytes.Repeat([]byte{0xff}, 1024)
	for ki, key := range specialKeys {
		k := key
		for _, m := range [][]byte{ffBuf[:0], ffBuf[:1], ffBuf[:15], ffBuf[:16], ffBuf[:17], ffBuf[:64], ffBuf[:1023], ffBuf[:1024]} {
			var want, got [16]byte
			useARM = false
			polySum(&want, m, &k)
			useARM = availARM
			polySum(&got, m, &k)
			if got != want {
				failf("poly1305 extremal key=%d len=%d got=%x want=%x", ki, len(m), got, want)
			}
		}
	}

	// All lengths 0..600 across alignments 0..7, plus direct updateASM tail test.
	for l := 0; l <= 600; l++ {
		for off := 0; off < 8; off++ {
			msg := buf[off : off+l]
			var want, got, gotDirect [16]byte
			useARM = false
			polySum(&want, msg, &k32)
			useARM = availARM
			polySum(&got, msg, &k32)
			if got != want {
				failf("poly1305 len=%d off=%d got=%x want=%x", l, off, got, want)
			}
			// Also call polyUpdateASM directly with the whole buffer (including 1..15 tail)
			var st polyMacState
			polyInit(&k32, &st)
			if len(msg) > 0 {
				polyUpdateASM(&st, msg)
			}
			polyFinalize(&gotDirect, &st.h, &st.s)
			if gotDirect != want {
				failf("poly1305 direct updateASM len=%d off=%d got=%x want=%x", l, off, gotDirect, want)
			}
		}
	}

	// Random sizes up to 256 KiB with random keys.
	for i := 0; i < 200; i++ {
		rng.Read(k32[:])
		l := rng.Intn(256 << 10)
		off := rng.Intn(16)
		var want, got [16]byte
		useARM = false
		polySum(&want, buf[off:off+l], &k32)
		useARM = availARM
		polySum(&got, buf[off:off+l], &k32)
		if got != want {
			failf("poly1305 rand i=%d len=%d got=%x want=%x", i, l, got, want)
		}
	}
	fmt.Println("poly1305 correctness: ok")
}

func testChaCha20Poly1305(buf []byte, rng *rand.Rand) {
	// RFC 8439 Section 2.8.2 AEAD test vector.
	key := unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := unhex("070000004041424344454647")
	aad := unhex("50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wantCT := unhex(
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b6116" +
			"1ae10b594f09e26a7e902ecbd0600691")

	useNEON = availNEON
	useARM = availARM
	aead, err := newAEAD(key)
	if err != nil {
		panic(err)
	}
	gotCT := aead.Seal(nil, nonce, pt, aad)
	if !bytes.Equal(gotCT, wantCT) {
		failf("aead RFC 8439 Seal got=%x want=%x", gotCT, wantCT)
	}
	gotPT, err := aead.Open(nil, nonce, gotCT, aad)
	if err != nil || !bytes.Equal(gotPT, pt) {
		failf("aead RFC 8439 Open err=%v", err)
	}

	// Test every length 0..1024 (covering 1-block, 2-block, 3-block=192, 4-block=256,
	// 6-block=384, and partial tails) across alignments and in-place vs out-of-place.
	dstGeneric := make([]byte, 65536+64)
	dstPatched := make([]byte, 65536+64)
	openOut := make([]byte, 65536+64)

	for l := 0; l <= 1024; l++ {
		off := l % 7
		msg := buf[off : off+l]
		ad := buf[100 : 100+(l%37)]

		useNEON, useARM = false, false
		ctWant := aead.Seal(dstGeneric[:0], nonce, msg, ad)

		useNEON, useARM = availNEON, availARM
		ctGot := aead.Seal(dstPatched[:0], nonce, msg, ad)
		if !bytes.Equal(ctGot, ctWant) {
			failf("aead Seal len=%d off=%d", l, off)
			continue
		}

		// Out-of-place Open
		ptGot, err := aead.Open(openOut[off:off], nonce, ctGot, ad)
		if err != nil || !bytes.Equal(ptGot, msg) {
			failf("aead Open len=%d err=%v", l, err)
		}

		// In-place Open (how crypto/tls decrypts records in-place!)
		copy(openOut[:len(ctGot)], ctGot)
		ptInPlace, err := aead.Open(openOut[:0], nonce, openOut[:len(ctGot)], ad)
		if err != nil || !bytes.Equal(ptInPlace, msg) {
			failf("aead Open in-place len=%d err=%v", l, err)
		}
	}

	// Random sizes up to 64 KiB (including 16384-byte TLS record size).
	sizes := []int{16384, 16384 - 1, 16384 + 1, 32768, 65536}
	for i := 0; i < 150; i++ {
		sizes = append(sizes, rng.Intn(65536))
	}
	for _, l := range sizes {
		rng.Read(key)
		rng.Read(nonce)
		aead, _ = newAEAD(key)
		off := rng.Intn(8)
		msg := buf[off : off+l]
		ad := buf[:13]

		useNEON, useARM = false, false
		ctWant := aead.Seal(dstGeneric[:0], nonce, msg, ad)

		useNEON, useARM = availNEON, availARM
		ctGot := aead.Seal(dstPatched[:0], nonce, msg, ad)
		if !bytes.Equal(ctGot, ctWant) {
			failf("aead rand Seal len=%d", l)
			continue
		}

		copy(openOut[:len(ctGot)], ctGot)
		ptGot, err := aead.Open(openOut[:0], nonce, openOut[:len(ctGot)], ad)
		if err != nil || !bytes.Equal(ptGot, msg) {
			failf("aead rand Open len=%d err=%v", l, err)
		}

		// Tamper check
		openOut[len(ctGot)-1] ^= 1
		if _, err := aead.Open(openOut[:0], nonce, openOut[:len(ctGot)], ad); err == nil {
			failf("aead tamper not detected len=%d", l)
		}
	}
	fmt.Println("chacha20poly1305 AEAD correctness (0..64KiB + in-place + tamper): ok")
}

func benchAll(buf []byte) {
	fmt.Println("\n=== Throughput on 16 KiB TLS records / 128 KiB SHA-256 blocks ===")

	// 1. SHA-256 (128 KiB blocks)
	blk128 := buf[:128<<10]
	for _, hw := range []bool{false, true} {
		useSHA2 = hw && availSHA2
		var total int
		t0 := time.Now()
		for time.Since(t0) < time.Second {
			for j := 0; j < 8; j++ {
				sha256.Sum256(blk128)
				total += len(blk128)
			}
		}
		el := time.Since(t0).Seconds()
		fmt.Printf("sha256 (hw=%-5v):           %6.1f MB/s\n", hw, float64(total)/el/1e6)
	}
	useSHA2 = availSHA2

	// 2. ChaCha20 NEON (16 KiB blocks)
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	blk16 := buf[:16<<10]
	out := make([]byte, len(blk16))
	{
		var k8 [8]uint32
		var n3 [3]uint32
		var ctr uint32
		var total int
		t0 := time.Now()
		for time.Since(t0) < time.Second {
			for j := 0; j < 32; j++ {
				ctr = 1
				xorKeyStreamNEON(out, blk16, &k8, &n3, &ctr)
				total += len(blk16)
			}
		}
		el := time.Since(t0).Seconds()
		fmt.Printf("chacha20 (neon=true ):        %6.1f MB/s\n", float64(total)/el/1e6)
	}

	// 3. Poly1305 (16 KiB blocks)
	var k32 [32]byte
	var tag [16]byte
	for _, hw := range []bool{false, true} {
		useARM = hw && availARM
		var total int
		t0 := time.Now()
		for time.Since(t0) < time.Second {
			for j := 0; j < 32; j++ {
				polySum(&tag, blk16, &k32)
				total += len(blk16)
			}
		}
		el := time.Since(t0).Seconds()
		fmt.Printf("poly1305 (asm=%-5v):         %6.1f MB/s\n", hw, float64(total)/el/1e6)
	}
	useARM = availARM

	// 4. ChaCha20-Poly1305 Open (16 KiB TLS records)
	ad := make([]byte, 13)
	aead, _ := newAEAD(key)
	ct := aead.Seal(nil, nonce, blk16, ad)
	for _, hw := range []bool{false, true} {
		useNEON = hw && availNEON
		useARM = hw && availARM
		var total int
		t0 := time.Now()
		for time.Since(t0) < 1500*time.Millisecond {
			for j := 0; j < 32; j++ {
				_, err := aead.Open(out[:0], nonce, ct, ad)
				if err != nil {
					panic(err)
				}
				total += len(blk16)
			}
		}
		el := time.Since(t0).Seconds()
		fmt.Printf("chacha20poly1305.Open (hw=%-5v): %6.1f MB/s\n", hw, float64(total)/el/1e6)
	}
	useNEON = availNEON
	useARM = availARM
}

func main() {
	availSHA2 = useSHA2
	availNEON = useNEON
	availARM = useARM
	fmt.Printf("CPU paths enabled: SHA2=%v NEON=%v ARM_VFPv3=%v\n", availSHA2, availNEON, availARM)
	if !availSHA2 || !availNEON || !availARM {
		failf("expected all hardware paths to be enabled on Kindle")
	}

	rng := rand.New(rand.NewSource(42))
	buf := make([]byte, 512<<10)
	rng.Read(buf)

	testSHA256(buf, rng)
	testPoly1305(buf, rng)
	testChaCha20Poly1305(buf, rng)
	benchAll(buf)

	if failures > 0 {
		fmt.Printf("\nRESULT: FAIL (%d failures)\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nRESULT: PASS")
}
