package active

import "testing"

func BenchmarkCmdPayloads(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CmdPayloads()
	}
}
