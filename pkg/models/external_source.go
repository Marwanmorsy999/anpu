package models

// Source identities for optional external integrations (katana, httpx,
// subfinder, dalfox, naabu, dnsx). Like Nuclei/ZAP, these tools are
// invoked only when installed; their output is normalized into the shared
// finding model.
const (
	SourceKatana    Source = "katana"
	SourceHttpx     Source = "httpx"
	SourceSubfinder Source = "subfinder"
	SourceDalfox    Source = "dalfox"
	SourceNaabu     Source = "naabu"
	SourceDNSx      Source = "dnsx"
)
