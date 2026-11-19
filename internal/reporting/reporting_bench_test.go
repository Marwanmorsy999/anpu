package reporting

import "testing"

func BenchmarkMdCell(b *testing.B) {
	in := "a|b\nc\td"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mdCell(in)
	}
}
