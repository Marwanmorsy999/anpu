package headers

// hsts.go — Strict-Transport-Security quality analysis.
//
// checkHSTSQuality is called by checkHSTS when an HSTS header is present.
// It parses the header value and emits one finding per identified weakness.
//
// The six checks mirror real-world failures observed in Qualys SSL Labs,
// securityheaders.com, and testssl.sh output:
//
//  1. max-age missing or zero           → Low
//  2. max-age < 30 days (2592000s)     → Medium  (too short to protect)
//  3. max-age < 6 months (15552000s)   → Low     (below preload minimum)
//  4. preload + max-age < 1 year       → Medium  (preload requirement unmet)
//  5. preload present, includeSubDomains absent → Medium (preload requires it)
//  6. includeSubDomains absent         → Info    (good practice on HTTPS)

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

const (
	hstsDays30  = 2592000  // 30 days in seconds — minimum meaningful protection
	hstsDays180 = 15552000 // 180 days — below preload list minimum
	hstsDays365 = 31536000 // 365 days — required for preload submission
)

// parseHSTS extracts max-age, includeSubDomains, and preload from an HSTS value.
// Returns maxAge=-1 if the directive is absent or unparseable.
func parseHSTS(value string) (maxAge int64, includeSubDomains, preload bool) {
	maxAge = -1
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)
		switch {
		case strings.HasPrefix(lower, "max-age="):
			raw := strings.TrimPrefix(lower, "max-age=")
			if n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
				maxAge = n
			}
		case lower == "includesubdomains":
			includeSubDomains = true
		case lower == "preload":
			preload = true
		}
	}
	return
}

// checkHSTSQuality inspects an HSTS header value and returns findings for each
// identified weakness. Called only when the Strict-Transport-Security header is
// present on an HTTPS response.
func checkHSTSQuality(value, target, url string) []models.Finding {
	maxAge, includeSubDomains, preload := parseHSTS(value)

	ev := models.Evidence{
		Observed: fmt.Sprintf("Strict-Transport-Security: %s", value),
		Location: "HTTP response header",
	}

	var out []models.Finding

	// 1. max-age missing or zero — HSTS has no effect.
	if maxAge < 0 {
		out = append(out, finding(
			"headers-hsts-missing-max-age",
			"HSTS header is present but max-age is missing",
			"The Strict-Transport-Security header is present but does not include a max-age directive. "+
				"Without max-age the browser does not cache the HSTS policy, so the header has no practical effect — "+
				"each visit is treated as if HSTS is absent.",
			models.SeverityLow,
			models.ConfidenceHigh,
			target, url, ev,
			"SSL stripping remains possible on the first request of each browsing session since the HSTS policy is never cached.",
			"Set a max-age of at least 15552000 (180 days), e.g. Strict-Transport-Security: max-age=15552000",
			"CWE-319",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
		))
		return out // remaining checks require a valid max-age
	}

	if maxAge == 0 {
		out = append(out, finding(
			"headers-hsts-max-age-zero",
			"HSTS max-age is set to zero (policy revoked)",
			"Strict-Transport-Security: max-age=0 instructs browsers to delete any previously cached HSTS policy for this host. "+
				"Unless this is an intentional removal during a migration away from HTTPS, this configuration leaves users unprotected.",
			models.SeverityLow,
			models.ConfidenceHigh,
			target, url, ev,
			"Browsers will immediately expire the HSTS cache entry, allowing future connections to be downgraded to HTTP.",
			"Set max-age to a positive value (e.g. 15552000) to ensure browsers enforce HTTPS.",
			"CWE-319",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
		))
		return out
	}

	// 2. max-age < 30 days — too short for meaningful SSL-stripping protection.
	if maxAge < hstsDays30 {
		out = append(out, finding(
			"headers-hsts-max-age-too-short",
			fmt.Sprintf("HSTS max-age is very short (%d seconds, less than 30 days)", maxAge),
			fmt.Sprintf(
				"The Strict-Transport-Security max-age of %d seconds is below 30 days (%d s). "+
					"An attacker who performs an SSL-stripping attack on a user's first visit can intercept traffic for the entire max-age window. "+
					"A very short max-age reduces this window but also reduces HSTS's effectiveness since users are repeatedly at risk on their first visit after expiry.",
				maxAge, hstsDays30,
			),
			models.SeverityMedium,
			models.ConfidenceHigh,
			target, url, ev,
			"Users who have not visited the site before (or whose HSTS cache has expired) remain vulnerable to SSL stripping during the first plain-HTTP request.",
			fmt.Sprintf("Increase max-age to at least %d (180 days). For long-term protection consider %d (1 year).", hstsDays180, hstsDays365),
			"CWE-319",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
				"https://hstspreload.org/",
			},
		))
	} else if maxAge < hstsDays180 {
		// 3. max-age >= 30 days but < 6 months — below preload minimum.
		out = append(out, finding(
			"headers-hsts-max-age-below-preload-min",
			fmt.Sprintf("HSTS max-age (%d seconds) is below the 180-day preload minimum", maxAge),
			fmt.Sprintf(
				"The Strict-Transport-Security max-age of %d seconds is less than 15552000 (180 days), "+
					"which is the minimum required for inclusion in the HSTS preload list. "+
					"While not an immediate security risk, a shorter max-age reduces HSTS protection for users whose cache entry has expired.",
				maxAge,
			),
			models.SeverityLow,
			models.ConfidenceHigh,
			target, url, ev,
			"HSTS cache entries expire more frequently, slightly widening the window during which SSL stripping could succeed on a returning visitor.",
			fmt.Sprintf("Increase max-age to at least %d (180 days). If preload submission is a goal, set max-age=%d (1 year).", hstsDays180, hstsDays365),
			"CWE-319",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
				"https://hstspreload.org/",
			},
		))
	}

	// 4. preload present but max-age < 1 year — preload submission requirement not met.
	if preload && maxAge < hstsDays365 {
		out = append(out, finding(
			"headers-hsts-preload-max-age-insufficient",
			fmt.Sprintf("HSTS preload directive present but max-age (%d s) is below 1-year preload requirement", maxAge),
			fmt.Sprintf(
				"The Strict-Transport-Security header includes the preload directive, signalling intent to be added to browser preload lists, "+
					"but the max-age of %d seconds is below the required minimum of %d (1 year). "+
					"Browsers will not accept this host for preload list submission in this state.",
				maxAge, hstsDays365,
			),
			models.SeverityMedium,
			models.ConfidenceHigh,
			target, url, ev,
			"The preload directive has no effect until all submission requirements are met; the site is not on any preload list solely because the header says 'preload'.",
			fmt.Sprintf("Set max-age=%d (1 year minimum), add includeSubDomains, and then submit to https://hstspreload.org/", hstsDays365),
			"CWE-319",
			[]string{"https://hstspreload.org/"},
		))
	}

	// 5. preload present but includeSubDomains absent — preload requires it.
	if preload && !includeSubDomains {
		out = append(out, finding(
			"headers-hsts-preload-missing-include-subdomains",
			"HSTS preload requires includeSubDomains but it is absent",
			"The Strict-Transport-Security header includes the preload directive but omits includeSubDomains. "+
				"The HSTS preload list specification requires that all subdomains also support HTTPS (enforced via includeSubDomains) "+
				"before a domain can be submitted for preloading.",
			models.SeverityMedium,
			models.ConfidenceHigh,
			target, url, ev,
			"The preload directive will be ignored by preload list operators; the site cannot be submitted for preloading in this state.",
			"Add includeSubDomains to the header after verifying that all subdomains serve valid HTTPS responses.",
			"CWE-319",
			[]string{"https://hstspreload.org/"},
		))
	}

	// 6. includeSubDomains absent on an HTTPS site — good practice, not critical.
	if !includeSubDomains {
		out = append(out, finding(
			"headers-hsts-missing-include-subdomains",
			"HSTS policy does not include includeSubDomains",
			"The Strict-Transport-Security header does not include the includeSubDomains directive. "+
				"Without it, subdomains of this host are not covered by the HSTS policy and may remain accessible over plain HTTP, "+
				"potentially allowing cookie theft via a subdomain that redirects to HTTP.",
			models.SeverityInfo,
			models.ConfidenceLow,
			target, url, ev,
			"Subdomains not covered by HSTS can be used to steal cookies scoped to the parent domain if those subdomains ever serve HTTP responses.",
			"Add includeSubDomains once all subdomains support HTTPS. Test carefully: this will break any subdomain that does not serve HTTPS.",
			"CWE-319",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
		))
	}

	return out
}
