// Package technology performs passive technology fingerprinting from
// HTTP headers, cookie names, and HTML/JS content — the same kind of
// signals a browser's "view source" would reveal. It never claims an
// exact version without direct evidence for that version string.
package technology

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// hostRoot returns scheme://host for a target URL, dropping any subpath.
// Well-known probes (readme.html, wp-json, xmlrpc) live at the host root.
func hostRoot(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimSuffix(raw, "/")
	}
	return u.Scheme + "://" + u.Host
}

// Detector implements scanner.Scanner for technology fingerprinting.
type Detector struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Detector { return &Detector{client: client} }

func (d *Detector) Name() string { return "technology" }

func (d *Detector) Available(ctx context.Context) bool { return true }

func (d *Detector) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	resp, err := d.client.Get(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("fetching target for technology detection: %w", err)
	}

	body := string(resp.Body)
	var techs []models.Technology

	techs = append(techs, detectFromHeader(resp.Header, "Server", serverSignatures)...)
	techs = append(techs, detectFromHeader(resp.Header, "X-Powered-By", poweredBySignatures)...)
	techs = append(techs, detectFromHeader(resp.Header, "X-AspNet-Version", aspNetSignatures)...)
	techs = append(techs, detectFromHeader(resp.Header, "X-AspNetMvc-Version", aspNetSignatures)...)
	techs = append(techs, detectFromHeader(resp.Header, "X-Generator", generatorHeaderSignatures)...)
	techs = append(techs, detectFromCookies(resp.Header)...)
	techs = append(techs, detectFromBody(body)...)
	techs = append(techs, detectCDN(resp.Header)...)

	techs = dedupTechnologies(techs)

	// WordPress mini-pack: version, user enumeration, xmlrpc surface —
	// only when WordPress was already detected, max 3 extra GETs.
	var findings []models.Finding
	if hasTechnology(techs, "WordPress") {
		wpTechs, wpFindings := d.probeWordPress(ctx, sc, techs)
		techs = append(techs, wpTechs...)
		findings = append(findings, wpFindings...)
		techs = dedupTechnologies(techs)
	}

	return scanner.StageResult{Technologies: techs, Findings: findings}, nil
}

// hasTechnology reports whether a technology name was detected.
func hasTechnology(techs []models.Technology, name string) bool {
	for _, t := range techs {
		if t.Name == name {
			return true
		}
	}
	return false
}

type signature struct {
	Name     string
	Category string
	Pattern  *regexp.Regexp // optional: extracts version as first capture group
}

var serverSignatures = []signature{
	{"nginx", "web-server", regexp.MustCompile(`(?i)nginx/?([\d.]+)?`)},
	{"Apache", "web-server", regexp.MustCompile(`(?i)apache/?([\d.]+)?`)},
	{"Microsoft-IIS", "web-server", regexp.MustCompile(`(?i)microsoft-iis/?([\d.]+)?`)},
	{"cloudflare", "cdn", regexp.MustCompile(`(?i)cloudflare`)},
	{"LiteSpeed", "web-server", regexp.MustCompile(`(?i)litespeed`)},
	{"Caddy", "web-server", regexp.MustCompile(`(?i)caddy`)},
	{"OpenResty", "web-server", regexp.MustCompile(`(?i)openresty/?([\d.]+)?`)},
	{"Apache Tomcat", "web-server", regexp.MustCompile(`(?i)(?:apache-coyote|tomcat)/?([\d.]+)?`)},
	{"Jetty", "web-server", regexp.MustCompile(`(?i)jetty(?:\(?([\d.]+[a-zA-Z0-9.\-]*))?`)},
	{"Kestrel", "web-server", regexp.MustCompile(`(?i)kestrel`)},
	{"Werkzeug", "web-server", regexp.MustCompile(`(?i)werkzeug/?([\d.]+)?`)},
	{"Gunicorn", "web-server", regexp.MustCompile(`(?i)gunicorn/?([\d.]+)?`)},
	{"AkamaiGHost", "cdn", regexp.MustCompile(`(?i)akamai[ggr]host`)},
}

var aspNetSignatures = []signature{
	{"ASP.NET", "backend", regexp.MustCompile(`(?i)([\d.]+)`)},
}

var generatorHeaderSignatures = []signature{
	{"Drupal", "cms", regexp.MustCompile(`(?i)drupal\s*([\d.]+)?`)},
}

var poweredBySignatures = []signature{
	{"PHP", "backend", regexp.MustCompile(`(?i)php/?([\d.]+)?`)},
	{"ASP.NET", "backend", regexp.MustCompile(`(?i)asp\.net`)},
	{"Express", "backend", regexp.MustCompile(`(?i)express`)},
	{"Next.js", "framework", regexp.MustCompile(`(?i)next\.js`)},
}

func detectFromHeader(h http.Header, headerName string, sigs []signature) []models.Technology {
	v := h.Get(headerName)
	if v == "" {
		return nil
	}
	var out []models.Technology
	for _, sig := range sigs {
		m := sig.Pattern.FindStringSubmatch(v)
		if m == nil {
			continue
		}
		version := ""
		if len(m) > 1 {
			version = m[1]
		}
		out = append(out, models.Technology{
			Name:       sig.Name,
			Category:   sig.Category,
			Version:    version,
			Confidence: 0.8,
			Evidence: models.Evidence{
				Observed: fmt.Sprintf("%s: %s", headerName, v),
				Location: "HTTP response header",
			},
		})
	}
	return out
}

// cookieSignatures maps well-known cookie name prefixes/exact-names to
// the technology that typically sets them.
var cookieSignatures = map[string]signature{
	"phpsessid":             {"PHP", "backend", nil},
	"asp.net_sessionid":     {"ASP.NET", "backend", nil},
	"laravel_session":       {"Laravel", "framework", nil},
	"connect.sid":           {"Express (connect/express-session)", "framework", nil},
	"csrftoken":             {"Django", "framework", nil},
	"django_language":       {"Django", "framework", nil},
	"_rails_session":        {"Ruby on Rails", "framework", nil},
	"wordpress_logged_in":   {"WordPress", "cms", nil},
	"wp-settings":           {"WordPress", "cms", nil},
	"wordpress_test_cookie": {"WordPress", "cms", nil},
	"ci_session":            {"CodeIgniter", "framework", nil},
	"jsessionid":            {"Java (Servlet container)", "backend", nil},
	"arraffinity":           {"Azure App Service", "hosting", nil},
	"awsalb":                {"AWS Elastic Load Balancer", "hosting", nil},
	"awsalbcors":            {"AWS Elastic Load Balancer", "hosting", nil},
	"__cf_bm":               {"Cloudflare", "cdn", nil},
}

// cookiePrefixSignatures matches cookie names by pattern (values carry
// pool/instance suffixes, e.g. BIGipServerpool_abc).
type cookiePrefixSig struct {
	pattern *regexp.Regexp
	sig     signature
}

var cookiePrefixSignatures = []cookiePrefixSig{
	{regexp.MustCompile(`(?i)^bigipserver`), signature{"F5 BIG-IP", "hosting", nil}},
	{regexp.MustCompile(`(?i)^ts[0-9a-f]{8,}$`), signature{"Blue Coat ProxySG", "security", nil}},
	{regexp.MustCompile(`(?i)^x-ms-`), signature{"Azure", "hosting", nil}},
}

func detectFromCookies(h http.Header) []models.Technology {
	var out []models.Technology
	var dummy http.Response
	dummy.Header = h
	addTech := func(name, category, observed string, confidence float64) {
		out = append(out, models.Technology{
			Name:       name,
			Category:   category,
			Confidence: confidence,
			Evidence: models.Evidence{
				Observed: observed,
				Location: "Set-Cookie response header",
			},
		})
	}
	for _, c := range dummy.Cookies() {
		lower := strings.ToLower(c.Name)
		if sig, ok := cookieSignatures[lower]; ok {
			addTech(sig.Name, sig.Category, fmt.Sprintf("cookie name: %s", c.Name), 0.6)
			continue
		}
		for _, ps := range cookiePrefixSignatures {
			if ps.pattern.MatchString(c.Name) {
				addTech(ps.sig.Name, ps.sig.Category, fmt.Sprintf("cookie name: %s", c.Name), 0.55)
				break
			}
		}
	}
	return out
}

// bodySignature matches HTML/JS body content. VersionAt, if > 0, is the
// capture-group index in Pattern that holds the version string.
type bodySignature struct {
	Name      string
	Category  string
	Pattern   *regexp.Regexp
	VersionAt int // 0 = no version capture
}

// bodySignatures match against raw HTML/JS body content. Kept conservative
// and specific to reduce false positives.
//
// VersionAt points to the capture group that holds the version string when
// it can be extracted directly from the matched token.
var bodySignatures = []bodySignature{
	// WordPress — wp-content/wp-includes path presence; version via generator tag
	{"WordPress", "cms",
		regexp.MustCompile(`(?i)wp-content/|wp-includes/`), 0},
	// React — no reliable inline version
	{"React", "js-framework",
		regexp.MustCompile(`(?i)data-reactroot|react-dom|__REACT_DEVTOOLS`), 0},
	// Vue.js
	{"Vue.js", "js-framework",
		regexp.MustCompile(`(?i)data-v-app|__vue__|vue\.js`), 0},
	// Angular writes ng-version="17.3.1" on the root element
	{"Angular", "js-framework",
		regexp.MustCompile(`(?i)ng-version="([\d.]+)"`), 1},
	// Next.js
	{"Next.js", "framework",
		regexp.MustCompile(`(?i)__NEXT_DATA__|/_next/static/`), 0},
	// jQuery — inline banner /*! jQuery v3.6.0 */ or script src filename
	{"jQuery", "js-library",
		regexp.MustCompile(`(?i)(?:jQuery(?:\s+JavaScript Library)?\s+v([\d.]+)|jquery[/\-]([\d.]+)(?:\.min)?\.js)`), 1},
	// Bootstrap — inline banner /*! Bootstrap v5.3.0 */ or filename
	{"Bootstrap", "css-framework",
		regexp.MustCompile(`(?i)(?:Bootstrap\s+v([\d.]+)|bootstrap[/\-]([\d.]+)(?:\.min)?(?:\.css|\.js))`), 1},
	// lodash — inline banner /*! lodash v4.17.21 */
	{"lodash", "js-library",
		regexp.MustCompile(`(?i)lodash(?:\s+v|-)([\d.]+)`), 1},
	// moment.js — inline banner //! moment.js 2.29.4
	{"moment", "js-library",
		regexp.MustCompile(`(?i)moment\.js\s+([\d.]+)`), 1},
	{"Shopify", "cms",
		regexp.MustCompile(`(?i)cdn\.shopify\.com|Shopify\.theme`), 0},
	{"Drupal", "cms",
		regexp.MustCompile(`(?i)Drupal\.settings|/sites/default/files/`), 0},
	{"Tailwind CSS", "css-framework",
		regexp.MustCompile(`(?i)cdn\.tailwindcss\.com|tailwind\.config|tailwindcss|tailwind\.min\.css`), 0},
	{"Google Tag Manager", "analytics",
		regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`), 0},
	{"Google Analytics", "analytics",
		regexp.MustCompile(`(?i)google-analytics\.com/analytics\.js|gtag\('config'`), 0},
	// --- CMS extras ---
	{"Joomla", "cms",
		regexp.MustCompile(`(?i)/media/jui/|/media/system/js/`), 0},
	{"TYPO3", "cms",
		regexp.MustCompile(`(?i)typo3conf/|typo3temp/`), 0},
	{"MediaWiki", "cms",
		regexp.MustCompile(`(?i)/load\.php\?|mw\.config|mediawiki\.`), 0},
	{"Ghost", "cms",
		regexp.MustCompile(`(?i)ghost-sdk|/ghost/api/`), 0},
	{"Wix", "cms",
		regexp.MustCompile(`(?i)parastorage\.com|wixstatic\.com|wix\.com`), 0},
	{"Webflow", "cms",
		regexp.MustCompile(`(?i)webflow\.(com|js)|w-webflow`), 0},
	{"vBulletin", "cms",
		regexp.MustCompile(`(?i)vbulletin`), 0},
	{"XenForo", "cms",
		regexp.MustCompile(`(?i)xenforo`), 0},
	{"phpBB", "cms",
		regexp.MustCompile(`(?i)phpbb`), 0},
	{"Discourse", "cms",
		regexp.MustCompile(`(?i)/assets/discourse|discourse\.js|discourse-cdn|discourse\.org`), 0},
	{"Magento", "cms",
		regexp.MustCompile(`(?i)mage/|Magento_|/static/version`), 0},
	{"PrestaShop", "cms",
		regexp.MustCompile(`(?i)prestashop`), 0},
	{"OpenCart", "cms",
		regexp.MustCompile(`(?i)index\.php\?route=|catalog/view/`), 0},
	{"WooCommerce", "cms",
		regexp.MustCompile(`(?i)woocommerce`), 0},
	{"BigCommerce", "cms",
		regexp.MustCompile(`(?i)cdn11\.bigcommerce\.com|bigcommerce\.com`), 0},
	{"HubSpot", "cms",
		regexp.MustCompile(`(?i)hs-scripts\.com|hubspot\.com`), 0},
	// --- JS frameworks / libraries ---
	{"SvelteKit", "js-framework",
		regexp.MustCompile(`__sveltekit|/_app/immutable/`), 0},
	{"Nuxt", "js-framework",
		regexp.MustCompile(`__NUXT__|/_nuxt/`), 0},
	{"Astro", "js-framework",
		regexp.MustCompile(`class="astro-`), 0},
	{"Gatsby", "js-framework",
		regexp.MustCompile(`id="gatsby-`), 0},
	{"Rails", "framework",
		regexp.MustCompile(`csrf-param|authenticity_token`), 0},
	{"Django", "framework",
		regexp.MustCompile(`csrfmiddlewaretoken`), 0},
	{"Blazor", "framework",
		regexp.MustCompile(`(?i)_blazor`), 0},
	{"Livewire", "framework",
		regexp.MustCompile(`(?i)livewire`), 0},
	{"Inertia.js", "framework",
		regexp.MustCompile(`data-page=["']\{`), 0},
	{"HTMX", "js-library",
		regexp.MustCompile(`hx-get|hx-post`), 0},
	{"Alpine.js", "js-library",
		regexp.MustCompile(`x-data`), 0},
	{"Ember.js", "js-framework",
		regexp.MustCompile(`ember-view`), 0},
	{"Knockout", "js-framework",
		regexp.MustCompile(`data-bind=`), 0},
	{"Chart.js", "js-library",
		regexp.MustCompile(`new Chart\(|Chart\.js`), 0},
	{"three.js", "js-library",
		regexp.MustCompile(`THREE\.`), 0},
	{"GSAP", "js-library",
		regexp.MustCompile(`gsap\.`), 0},
	{"Swiper", "js-library",
		regexp.MustCompile(`new Swiper\(|swiper-bundle`), 0},
	{"Axios", "js-library",
		regexp.MustCompile(`axios\.(?:get|post|min\.js)`), 0},
	{"Sails", "framework",
		regexp.MustCompile(`sails\.io`), 0},
	{"Video.js", "js-library",
		regexp.MustCompile(`(?i)video\.js|videojs`), 0},
	{"JW Player", "js-library",
		regexp.MustCompile(`(?i)jwplayer`), 0},
	// --- Auth / identity ---
	{"Auth0", "authentication",
		regexp.MustCompile(`(?i)cdn\.auth0\.com|auth0\.com`), 0},
	{"Okta", "authentication",
		regexp.MustCompile(`(?i)okta-signin-widget|okta\.com`), 0},
	{"Firebase", "backend",
		regexp.MustCompile(`(?i)firebasejs|gstatic\.com/firebasejs`), 0},
	{"Supabase", "backend",
		regexp.MustCompile(`(?i)supabase-js`), 0},
	{"MSAL", "authentication",
		regexp.MustCompile(`(?i)login\.microsoftonline\.com|msal`), 0},
	{"AWS Amplify", "backend",
		regexp.MustCompile(`(?i)aws-amplify`), 0},
	{"Clerk", "authentication",
		regexp.MustCompile(`(?i)clerk\.com|clerk\.js|__clerk|ClerkProvider`), 0},
	{"reCAPTCHA", "captcha",
		regexp.MustCompile(`(?i)google\.com/recaptcha`), 0},
	{"hCaptcha", "captcha",
		regexp.MustCompile(`(?i)hcaptcha\.com`), 0},
	{"Cloudflare Turnstile", "captcha",
		regexp.MustCompile(`(?i)challenges\.cloudflare\.com`), 0},
	// --- Payments / maps / monitoring ---
	{"Stripe", "payment",
		regexp.MustCompile(`(?i)js\.stripe\.com`), 0},
	{"PayPal", "payment",
		regexp.MustCompile(`(?i)paypal\.com/sdk/js`), 0},
	{"Plaid", "payment",
		regexp.MustCompile(`(?i)cdn\.plaid\.com`), 0},
	{"Google Maps", "maps",
		regexp.MustCompile(`(?i)maps\.googleapis\.com/maps/api/js`), 0},
	{"Mapbox", "maps",
		regexp.MustCompile(`(?i)api\.mapbox\.com`), 0},
	{"Leaflet", "maps",
		regexp.MustCompile(`(?i)leaflet\.(js|css)|L\.map\(|leaflet-container|/leaflet/`), 0},
	{"Sentry", "monitoring",
		regexp.MustCompile(`(?i)sentry-cdn|browser\.sentry-cdn`), 0},
	{"New Relic", "monitoring",
		regexp.MustCompile(`(?i)js-agent\.newrelic\.com|NREUM`), 0},
	{"Datadog RUM", "monitoring",
		regexp.MustCompile(`(?i)datadoghq-browser-agent`), 0},
	{"Bugsnag", "monitoring",
		regexp.MustCompile(`(?i)bugsnag`), 0},
	{"Rollbar", "monitoring",
		regexp.MustCompile(`(?i)rollbar`), 0},
	// --- Video / search / chat / consent ---
	{"YouTube embed", "video",
		regexp.MustCompile(`(?i)youtube\.com/embed`), 0},
	{"Vimeo", "video",
		regexp.MustCompile(`(?i)player\.vimeo\.com`), 0},
	{"Algolia", "search",
		regexp.MustCompile(`(?i)algolianet\.com`), 0},
	{"Intercom", "chat",
		regexp.MustCompile(`(?i)widget\.intercom\.io`), 0},
	{"Drift", "chat",
		regexp.MustCompile(`(?i)js\.driftt\.com`), 0},
	{"Crisp", "chat",
		regexp.MustCompile(`(?i)client\.crisp\.chat`), 0},
	{"Tawk.to", "chat",
		regexp.MustCompile(`(?i)embed\.tawk\.to`), 0},
	{"OneTrust", "consent",
		regexp.MustCompile(`(?i)cdn\.cookielaw\.org|onetrust`), 0},
	{"Cookiebot", "consent",
		regexp.MustCompile(`(?i)consent\.cookiebot\.com`), 0},
}

// generatorPattern matches <meta name="generator" content="Name Version">
// in either attribute order.
var generatorPattern = regexp.MustCompile(
	`(?i)<meta[^>]+name=["'']?generator["'']?[^>]+content=["'']([^"']+)["'']|` +
		`<meta[^>]+content=["'']([^"']+)["''][^>]+name=["'']?generator["'']?`,
)

// knownGenerators maps generator tag prefixes to Technology fields.
var knownGenerators = []struct {
	prefix   string
	name     string
	category string
}{
	{"wordpress", "WordPress", "cms"},
	{"joomla!", "Joomla", "cms"},
	{"drupal", "Drupal", "cms"},
	{"typo3", "TYPO3", "cms"},
	{"mediawiki", "MediaWiki", "cms"},
	{"ghost", "Ghost", "cms"},
	{"gatsby", "Gatsby", "framework"},
	{"hugo", "Hugo", "framework"},
	{"jekyll", "Jekyll", "framework"},
	{"wix", "Wix", "cms"},
	{"squarespace", "Squarespace", "cms"},
}

// detectFromBody scans the page body for technology fingerprints and, where
// possible, extracts the exact version from inline banners or attribute values.
func detectFromBody(body string) []models.Technology {
	if len(body) > 2_000_000 {
		body = body[:2_000_000]
	}
	var out []models.Technology

	for _, sig := range bodySignatures {
		m := sig.Pattern.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		version := ""
		if sig.VersionAt > 0 {
			for i := sig.VersionAt; i < len(m); i++ {
				if m[i] != "" {
					version = m[i]
					break
				}
			}
		}
		confidence := 0.65
		location := "HTML/JavaScript response body"
		observed := fmt.Sprintf("matched pattern in page content: %q", truncate(m[0], 80))
		// Content-mention softening: bare-word body hits (e.g.
		// "WooCommerce" on a /vs/woocommerce comparison page) are
		// page-copy mentions, not stack signals. Flag the source so
		// downstream stack gates don't treat them as detected tech.
		if contentMentionOnly[sig.Name] {
			confidence = 0.35
			location = "page content (mention, not asset signal)"
			observed = fmt.Sprintf("mentioned-in-content (not detected): %q", truncate(m[0], 80))
		}
		out = append(out, models.Technology{
			Name:       sig.Name,
			Category:   sig.Category,
			Version:    version,
			Confidence: confidence,
			Evidence: models.Evidence{
				Observed: observed,
				Location: location,
			},
		})
	}

	out = append(out, detectFromGenerator(body)...)
	return out
}

// contentMentionOnly marks body signatures whose bare-word pattern fires
// on marketing/comparison copy. These stay in the report as low-confidence
// mentions so the signal isn't lost, but stack-gated stages must ignore
// them (see hasTechnology callers).
var contentMentionOnly = map[string]bool{
	"Magento":     true,
	"WooCommerce": true,
}

// detectFromGenerator extracts technology and version from <meta name="generator">.
// Many CMSes and frameworks emit this tag with an exact version.
func detectFromGenerator(body string) []models.Technology {
	matches := generatorPattern.FindAllStringSubmatch(body, -1)
	var out []models.Technology
	for _, m := range matches {
		content := m[1]
		if content == "" {
			content = m[2]
		}
		content = strings.TrimSpace(content)
		if content == "" {
			continue
		}
		lower := strings.ToLower(content)
		for _, kg := range knownGenerators {
			if !strings.HasPrefix(lower, kg.prefix) {
				continue
			}
			// Version is everything after the product name, stripped of leading spaces/v.
			version := strings.TrimLeft(content[len(kg.prefix):], " vV")
			out = append(out, models.Technology{
				Name:       kg.name,
				Category:   kg.category,
				Version:    version,
				Confidence: 0.85,
				Evidence: models.Evidence{
					Observed: fmt.Sprintf("meta[name=generator]: %q", truncate(content, 80)),
					Location: "HTML meta tag",
				},
			})
			break
		}
	}
	return out
}

func detectCDN(h http.Header) []models.Technology {
	var out []models.Technology
	if h.Get("CF-Ray") != "" || h.Get("CF-Cache-Status") != "" {
		out = append(out, models.Technology{
			Name: "Cloudflare", Category: "cdn", Confidence: 0.9,
			Evidence: models.Evidence{Observed: "CF-Ray/CF-Cache-Status header present", Location: "HTTP response header"},
		})
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "cloudfront") || h.Get("X-Amz-Cf-Id") != "" {
		out = append(out, models.Technology{
			Name: "Amazon CloudFront", Category: "cdn", Confidence: 0.9,
			Evidence: models.Evidence{Observed: "X-Amz-Cf-Id header present", Location: "HTTP response header"},
		})
	}
	if h.Get("X-Vercel-Id") != "" {
		out = append(out, models.Technology{
			Name: "Vercel", Category: "hosting", Confidence: 0.9,
			Evidence: models.Evidence{Observed: "X-Vercel-Id header present", Location: "HTTP response header"},
		})
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "akamai") || h.Get("X-Akamai-Transformed") != "" {
		out = append(out, models.Technology{
			Name: "Akamai", Category: "cdn", Confidence: 0.85,
			Evidence: models.Evidence{Observed: "Akamai server/header signature present", Location: "HTTP response header"},
		})
	}
	if h.Get("X-Iinfo") != "" || strings.Contains(strings.ToLower(h.Get("X-CDN")), "imperva") ||
		strings.Contains(strings.ToLower(h.Get("X-CDN")), "incapsula") {
		out = append(out, models.Technology{
			Name: "Imperva", Category: "cdn", Confidence: 0.85,
			Evidence: models.Evidence{Observed: "X-Iinfo / X-CDN Imperva header present", Location: "HTTP response header"},
		})
	}
	if h.Get("X-Sucuri-ID") != "" || h.Get("X-Sucuri-Cache") != "" {
		out = append(out, models.Technology{
			Name: "Sucuri", Category: "cdn", Confidence: 0.9,
			Evidence: models.Evidence{Observed: "X-Sucuri-ID/Cache header present", Location: "HTTP response header"},
		})
	}
	return out
}

// wpReadmeVersion extracts "Stable tag: X.Y" from readme.html.
var wpReadmeVersion = regexp.MustCompile(`(?im)^stable tag:\s*([0-9][0-9a-zA-Z.\-]*)\s*$`)

// wpUserEntry matches one wp-json user object with id + slug.
var wpUserEntry = regexp.MustCompile(`(?i)\{[^{}]*"id"\s*:\s*(\d+)[^{}]*?"slug"\s*:\s*"([^"]+)"`)

// probeWordPress runs the WordPress mini-pack: exact version via
// readme.html (only when not already known), user enumeration via
// wp-json, and xmlrpc surface check. Max 3 extra GETs, read-only.
func (d *Detector) probeWordPress(ctx context.Context, sc *scanner.ScanContext, techs []models.Technology) ([]models.Technology, []models.Finding) {
	var out []models.Technology
	var findings []models.Finding
	base := hostRoot(sc.Target.Raw)

	get := func(path string) (int, []byte) {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		resp, err := d.client.Get(rctx, base+path)
		if err != nil || resp == nil {
			return 0, nil
		}
		return resp.StatusCode, resp.Body
	}

	// 1. Exact version from readme.html (skip when generator already gave one).
	known := ""
	for _, t := range techs {
		if t.Name == "WordPress" && t.Version != "" {
			known = t.Version
		}
	}
	if known == "" {
		if code, body := get("/readme.html"); code == 200 && len(body) > 0 {
			if m := wpReadmeVersion.FindSubmatch(body); m != nil {
				out = append(out, models.Technology{
					Name: "WordPress", Category: "cms", Version: string(m[1]), Confidence: 0.9,
					Evidence: models.Evidence{
						Observed: fmt.Sprintf("readme.html Stable tag: %s", string(m[1])),
						Location: "readme.html",
					},
				})
			}
		}
	}

	// 2. User enumeration via the REST API.
	if code, body := get("/wp-json/wp/v2/users"); code == 200 && len(body) > 0 {
		matches := wpUserEntry.FindAllSubmatch(body, -1)
		if len(matches) > 0 {
			slugs := []string{}
			for i, m := range matches {
				if i >= 10 {
					break
				}
				slugs = append(slugs, string(m[2]))
			}
			extra := ""
			if len(matches) > 10 {
				extra = fmt.Sprintf(" (showing 10 of %d)", len(matches))
			}
			findings = append(findings, models.Finding{
				ID:    "tech-wp-user-enum",
				Title: fmt.Sprintf("WordPress user enumeration exposed (%d user(s))", len(matches)),
				Description: fmt.Sprintf(
					"The REST API endpoint /wp-json/wp/v2/users lists %d user account(s)%s, disclosing login names that aid password-guessing attacks.",
					len(matches), extra,
				),
				Severity:   models.SeverityLow,
				Confidence: models.ConfidenceHigh,
				Category:   models.CategoryExposure,
				CWE:        "CWE-200",
				Target:     sc.Target.Raw,
				URL:        base + "/wp-json/wp/v2/users",
				Evidence: models.Evidence{
					Observed:       "user slugs: " + strings.Join(slugs, ", "),
					Location:       "/wp-json/wp/v2/users",
					RequestSummary: fmt.Sprintf("GET %s/wp-json/wp/v2/users", base),
				},
				Impact:          "Exposed usernames halve brute-force effort (attacker needs only the password).",
				Remediation:     "Restrict /wp-json/wp/v2/users to authenticated users or disable user enumeration via a security plugin / filter.",
				Source:          models.SourceTechnology,
				DetectionMethod: "WordPress REST API user enumeration check",
				FirstSeen:       time.Now(),
			})
		}
	}

	// 3. xmlrpc.php surface: 405 with an XML-RPC fault means the
	// endpoint is live (brute-force amplification surface).
	if code, body := get("/xmlrpc.php"); code == 405 && len(body) > 0 &&
		strings.Contains(strings.ToLower(string(body)), "xml-rpc") {
		findings = append(findings, models.Finding{
			ID:          "tech-wp-xmlrpc",
			Title:       "WordPress XML-RPC interface enabled",
			Description: "xmlrpc.php responds, exposing the XML-RPC API (system.multicall enables password-guessing amplification: hundreds of attempts per request) and pingback SSRF primitives.",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceHigh,
			Category:    models.CategoryExposure,
			CWE:         "CWE-307",
			Target:      sc.Target.Raw,
			URL:         base + "/xmlrpc.php",
			Evidence: models.Evidence{
				Observed:       "HTTP 405 with XML-RPC fault body",
				Location:       "/xmlrpc.php",
				RequestSummary: fmt.Sprintf("GET %s/xmlrpc.php", base),
			},
			Impact:          "Amplified credential guessing and pingback-based SSRF/port-scanning via XML-RPC.",
			Remediation:     "Disable XML-RPC if unused (filter xmlrpc_enabled), or restrict it and enforce strong passwords with rate limiting.",
			References:      []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_for_XMLRPC"},
			Source:          models.SourceTechnology,
			DetectionMethod: "WordPress xmlrpc.php availability check",
			FirstSeen:       time.Now(),
		})
	}

	return out, findings
}

func dedupTechnologies(in []models.Technology) []models.Technology {
	seen := map[string]bool{}
	byName := map[string]int{}
	var out []models.Technology
	for _, t := range in {
		lowerName := strings.ToLower(strings.TrimSpace(t.Name))
		key := lowerName + "|" + t.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		// Versioned wins both directions, case-insensitive:
		// bare "wordpress" loses to "WordPress 6.4.2" regardless of order.
		if idx, ok := byName[lowerName]; ok {
			existing := out[idx]
			if existing.Version == "" && t.Version != "" {
				out[idx] = t
				continue
			}
			if existing.Version != "" && t.Version == "" {
				continue
			}
			// Both versioned (or both bare with different casing): keep first,
			// but prefer the versioned entry already stored. Exact dupes
			// already skipped via seen, so differing versions both survive
			// only if both carry versions.
			if existing.Version != "" && t.Version != "" && existing.Version != t.Version {
				// Keep both distinct versions (different evidence).
			} else {
				continue
			}
		}
		if _, ok := byName[lowerName]; !ok {
			byName[lowerName] = len(out)
		}
		out = append(out, t)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
