// Local patch (hwsha): expose the 32-bit ARM SHA-2 crypto extension.
// internal/cpu.HWCap2 is filled from AT_HWCAP2 by the runtime (archauxv)
// before any package initialisation runs. Linux/FreeBSD HWCAP2_SHA2 = 1<<3.

package cpu

import "internal/cpu"

const hwcap2_SHA2 = 1 << 3

var ARMHasSHA2 = cpu.HWCap2&hwcap2_SHA2 != 0
