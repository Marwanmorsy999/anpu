package favicon

import (
	"testing"
)

func TestIsImageMagic(t *testing.T) {
	if !isImageMagic([]byte("\x89PNG\r\n\x1a\nrest")) {
		t.Fatal("PNG must pass")
	}
	if !isImageMagic([]byte("\x00\x00\x01\x00rest")) {
		t.Fatal("ICO must pass")
	}
	if !isImageMagic([]byte("\xff\xd8\xff rest")) {
		t.Fatal("JPEG must pass")
	}
	if !isImageMagic([]byte("GIF89arest")) {
		t.Fatal("GIF must pass")
	}
	if !isImageMagic([]byte("<html><svg viewBox=\"0 0 1 1\">")) {
		t.Fatal("SVG must pass")
	}
	if isImageMagic([]byte("<!DOCTYPE html><html><body>logo page")) {
		t.Fatal("HTML fallback must fail the gate")
	}
	if isImageMagic([]byte("")) {
		t.Fatal("empty must fail the gate")
	}
}
