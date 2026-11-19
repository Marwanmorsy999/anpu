# Refresh generated man page.
man:
	go test -tags genman -run TestGenMan ./cmd/anpu/

.PHONY: man