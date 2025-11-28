package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func decodeMaybeUTF16(b []byte) string {
	if len(b) >= 2 {
		if b[0] == 0xff && b[1] == 0xfe {
			b = b[2:]
			if len(b)%2 != 0 {
				b = append(b, 0)
			}
			u16 := make([]uint16, 0, len(b)/2)
			for i := 0; i < len(b); i += 2 {
				u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
			}
			r := utf16.Decode(u16)
			return string(r)
		} else if b[0] == 0xfe && b[1] == 0xff {
			b = b[2:]
			if len(b)%2 != 0 {
				b = append(b, 0)
			}
			u16 := make([]uint16, 0, len(b)/2)
			for i := 0; i < len(b); i += 2 {
				u16 = append(u16, uint16(b[i])<<8|uint16(b[i+1]))
			}
			r := utf16.Decode(u16)
			return string(r)
		}
	}
	return string(b)
}

func pickHashByLen(n int) string {
	switch n {
	case 16:
		return "md5"
	case 20:
		return "sha1"
	case 32:
		return "sha256"
	case 48:
		return "sha384"
	case 64:
		return "sha512"
	default:
		return ""
	}
}

func getHashFunc(name string) func() hash.Hash {
	switch strings.ToLower(name) {
	case "md5":
		return md5.New
	case "sha1":
		return sha1.New
	case "sha256":
		return sha256.New
	case "sha384":
		return sha512.New384
	case "sha512":
		return sha512.New
	default:
		return nil
	}
}

func parseAlphabetsFromMask(mask string) [][]rune {
	var alnumLower = []rune("abcdefghijklmnopqrstuvwxyz")
	var alnumUpper = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var digits = []rune("0123456789")

	res := make([][]rune, 0, len(mask))
	for _, ch := range mask {
		switch ch {
		case 'a':
			merged := make([]rune, 0, len(alnumLower)+len(alnumUpper)+len(digits))
			merged = append(merged, alnumLower...)
			merged = append(merged, alnumUpper...)
			merged = append(merged, digits...)
			res = append(res, merged)
		case 'd':
			res = append(res, digits)
		case 'l':
			res = append(res, alnumLower)
		case 'u':
			res = append(res, alnumUpper)
		default:
			die("Unknown mask character: %c", ch)
		}
	}
	return res
}

func productCounts(alphabets [][]rune) uint64 {
	var total uint64 = 1
	for _, a := range alphabets {
		total *= uint64(len(a))
	}
	return total
}

func main() {
	mask := flag.String("m", "", "mask, e.g. aaadd (required)")
	flag.Parse()
	if *mask == "" {
		die("Usage: go run crack.go -m <mask> <file>")
	}
	if flag.NArg() < 1 {
		die("Provide input file produced by gen.py")
	}
	filename := flag.Arg(0)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		die("Read file: %v", err)
	}
	text := strings.TrimSpace(decodeMaybeUTF16(data))
	parts := strings.Split(text, "*")
	if len(parts) < 9 {
		die("Expected 9 '*' separated hex fields, got %d fields", len(parts))
	}

	Ni, err := hex.DecodeString(parts[0])
	if err != nil {
		die("Ni hex: %v", err)
	}
	Nr, err := hex.DecodeString(parts[1])
	if err != nil {
		die("Nr hex: %v", err)
	}
	gx, err := hex.DecodeString(parts[2])
	if err != nil {
		die("g_x hex: %v", err)
	}
	gy, err := hex.DecodeString(parts[3])
	if err != nil {
		die("g_y hex: %v", err)
	}
	Ci, err := hex.DecodeString(parts[4])
	if err != nil {
		die("Ci hex: %v", err)
	}
	Cr, err := hex.DecodeString(parts[5])
	if err != nil {
		die("Cr hex: %v", err)
	}
	SAi, err := hex.DecodeString(parts[6])
	if err != nil {
		die("SAi hex: %v", err)
	}
	IDr, err := hex.DecodeString(parts[7])
	if err != nil {
		die("IDr hex: %v", err)
	}
	targetHash, err := hex.DecodeString(parts[8])
	if err != nil {
		die("HASH hex: %v", err)
	}

	hashname := pickHashByLen(len(targetHash))
	if hashname == "" {
		die("Unknown hash length: %d bytes", len(targetHash))
	}
	hfunc := getHashFunc(hashname)
	if hfunc == nil {
		die("Unsupported hash: %s", hashname)
	}
	fmt.Printf("Detected hash: %s (%d bytes)\n", hashname, len(targetHash))

	data1 := append(Ni, Nr...)
	data2 := bytes.Join([][]byte{gy, gx, Cr, Ci, SAi, IDr}, []byte{})

	alphabets := parseAlphabetsFromMask(*mask)
	total := productCounts(alphabets)
	fmt.Printf("Mask: %s -> positions: %d, total combinations: %d\n", *mask, len(alphabets), total)

	indices := make([]int, len(alphabets))
	var done uint32 = 0
	var attempts uint64 = 0
	start := time.Now()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	buildPassword := func() string {
		r := make([]rune, len(alphabets))
		for i := range alphabets {
			r[i] = alphabets[i][indices[i]]
		}
		return string(r)
	}

	go func() {
		for {
			select {
			case <-ticker.C:
				el := time.Since(start)
				a := atomic.LoadUint64(&attempts)
				speed := float64(a) / el.Seconds()
				percent := float64(a) / float64(total) * 100.0
				curr := buildPassword()
				fmt.Printf("Tried: %d / %d (%.6f%%), speed: %.0f tries/s, elapsed: %s, current: %s\n",
					a, total, percent, speed, el.Truncate(time.Second), curr)
			case <-interrupt:
				atomic.StoreUint32(&done, 1)
				return
			}
		}
	}()

	found := false
	var foundPw string
mainloop:
	for {
		pw := []byte(buildPassword())

		h1 := hmac.New(hfunc, pw)
		h1.Write(data1)
		skeyid := h1.Sum(nil)

		h2 := hmac.New(hfunc, skeyid)
		h2.Write(data2)
		computed := h2.Sum(nil)

		atomic.AddUint64(&attempts, 1)

		if hmac.Equal(computed, targetHash) {
			found = true
			foundPw = string(pw)
			break mainloop
		}

		for i := len(indices) - 1; i >= 0; i-- {
			indices[i]++
			if indices[i] < len(alphabets[i]) {
				break
			}
			indices[i] = 0
			if i == 0 {
				break mainloop
			}
		}
		if atomic.LoadUint32(&done) == 1 {
			fmt.Println("\nInterrupted by user")
			break
		}
	}

	elapsed := time.Since(start)
	if found {
		fmt.Printf("\nFOUND password: %s\nAttempts: %d, elapsed: %s, speed: %.0f tries/s\n",
			foundPw, atomic.LoadUint64(&attempts), elapsed.Truncate(time.Second),
			float64(atomic.LoadUint64(&attempts))/elapsed.Seconds())
	} else {
		fmt.Printf("\nPassword NOT found. Attempts: %d, elapsed: %s, speed: %.0f tries/s\n",
			atomic.LoadUint64(&attempts), elapsed.Truncate(time.Second),
			float64(atomic.LoadUint64(&attempts))/elapsed.Seconds())
	}
}
