// Package config provides configuration management with age-encrypted secrets.
//
// The bech32 encoding logic in this file is derived from
// filippo.io/age/internal/bech32, which is based on the BIP-0173 reference
// implementation by Takatoshi Nakagawa.
//
// Copyright (c) 2017 Takatoshi Nakagawa
// Copyright (c) 2019 The age Authors
// Licensed under the MIT License.
package config

import "strings"

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Generator = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk & 0x1ffffff) << 5
		chk ^= uint32(v)
		for i := range 5 {
			if (top>>i)&1 == 1 {
				chk ^= bech32Generator[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	h := []byte(strings.ToLower(hrp))
	ret := make([]byte, 0, len(h)*2+1)
	for _, c := range h {
		ret = append(ret, c>>5)
	}
	ret = append(ret, 0)
	for _, c := range h {
		ret = append(ret, c&31)
	}
	return ret
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	ret := make([]byte, 6)
	for p := range 6 {
		ret[p] = byte(mod>>(5*(5-p))) & 31
	}
	return ret
}

// bech32ConvertBits converts a byte slice from frombits-bit groups to tobits-bit groups.
func bech32ConvertBits(data []byte, frombits, tobits byte, pad bool) []byte {
	var ret []byte
	acc := uint32(0)
	bits := byte(0)
	maxv := byte(1<<tobits - 1)
	for _, value := range data {
		acc = acc<<frombits | uint32(value)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte(acc>>bits)&maxv)
		}
	}
	if pad && bits > 0 {
		ret = append(ret, byte(acc<<(tobits-bits))&maxv)
	}
	return ret
}

// encodeAGESecretKey encodes a 32-byte Curve25519 scalar as an
// "AGE-SECRET-KEY-1..." bech32 string compatible with age.ParseX25519Identity.
func encodeAGESecretKey(scalar []byte) string {
	const hrp = "age-secret-key-"
	values := bech32ConvertBits(scalar, 8, 5, true)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, p := range values {
		sb.WriteByte(bech32Charset[p])
	}
	for _, p := range bech32CreateChecksum(hrp, values) {
		sb.WriteByte(bech32Charset[p])
	}
	return strings.ToUpper(sb.String())
}
