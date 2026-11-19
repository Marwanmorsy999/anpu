package sstiexpand

import "testing"

func BenchmarkStripVolatile(b *testing.B) {
	body := "prefix " + "abcdef0123456789abcdef0123456789 " + "suffix 49 " + "1234567890abcdef1234567890abcdef"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stripVolatile(body)
	}
}
