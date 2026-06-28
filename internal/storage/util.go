package storage

func clearSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func validKeyLen(n byte) bool { return n == 8 || n == 16 || n == 24 }
