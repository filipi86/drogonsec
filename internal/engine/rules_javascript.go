package engine

import "github.com/filipi86/drogonsec/internal/config"

func javascriptRules() []Rule {
	return []Rule{
		// A05:2025 - eval() injection
		{
			ID:       "JS-001",
			Language: config.LangJavaScript,
			Severity: config.SeverityCritical,
			Title:    "Code injection via eval()",
			Description: "eval() executes arbitrary JavaScript code. User-controlled input in eval() " +
				"enables complete application compromise.",
			Pattern: mustCompile(`\beval\s*\(`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-95",
			CVSS:    9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/95.html",
			},
			Remediation: "Remove all uses of eval(). Use JSON.parse() for JSON data, or refactor to avoid dynamic code execution.",
		},

		// A05:2025 - innerHTML XSS
		{
			ID:       "JS-002",
			Language: config.LangJavaScript,
			Severity: config.SeverityHigh,
			Title:    "DOM-based XSS via innerHTML",
			Description: "Assigning user-controlled content to innerHTML parses and executes HTML, " +
				"enabling Cross-Site Scripting attacks.",
			Pattern: mustCompile(`\.innerHTML\s*=`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-79",
			CVSS:    7.4,
			References: []string{
				"https://owasp.org/Top10/2025/A05_2025-Injection/",
				"https://cwe.mitre.org/data/definitions/79.html",
			},
			Remediation: "Use textContent for text data. Use DOMPurify.sanitize() if HTML must be rendered. Prefer createElement/appendChild.",
		},

		// A05:2025 - document.write XSS
		{
			ID:       "JS-003",
			Language: config.LangJavaScript,
			Severity: config.SeverityHigh,
			Title:    "DOM-based XSS via document.write()",
			Description: "document.write() with user-controlled content renders arbitrary HTML/JavaScript, " +
				"enabling XSS attacks.",
			Pattern: mustCompile(`document\.write\s*\(`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-79",
			CVSS:    7.4,
			References: []string{
				"https://cwe.mitre.org/data/definitions/79.html",
			},
			Remediation: "Avoid document.write(). Use DOM manipulation methods (createElement, appendChild) instead.",
		},

		// A04:2025 - Hardcoded secrets
		{
			ID:       "JS-004",
			Language: config.LangJavaScript,
			Severity: config.SeverityHigh,
			Title:    "Hardcoded API key or secret",
			Description: "Hardcoded secrets in JavaScript/TypeScript source code are exposed to all " +
				"users who can access the source (especially frontend code).",
			Pattern: mustCompile(`(?i)(apiKey|api_key|secret|password|token|passwd)\s*[:=]\s*["'][^"']{8,}["']`),
			// Suppress only unambiguous placeholders/examples. We deliberately do
			// NOT suppress values that merely contain a security word: a real
			// secret can read "secretLiveDbValue...", and dropping those caused a
			// false negative on exactly what this rule must catch (audit finding).
			AntiPattern: mustCompile(`(?i)[:=]\s*["'][^"']*(fake|dummy|example|sample|placeholder|changeme|your[-_]|redacted|test[-_]|foobar|\.\.\.|xxx|<[^>]+>|\{\{)`),
			OWASP:       config.OWASP_A04_CryptographicFailures,
			CWE:         "CWE-259",
			CVSS:        8.0,
			References: []string{
				"https://cwe.mitre.org/data/definitions/259.html",
			},
			Remediation: "Use environment variables (process.env.API_KEY). For frontend, use a backend proxy to hide credentials from clients.",
		},

		// A02:2025 - Prototype pollution
		{
			ID:       "JS-005",
			Language: config.LangJavaScript,
			Severity: config.SeverityHigh,
			Title:    "Prototype pollution vulnerability",
			Description: "Merging user-controlled objects without protection can modify Object.prototype, " +
				"affecting all objects in the application.",
			Pattern: mustCompile(`(__proto__|constructor\.prototype)`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration,
			CWE:     "CWE-1321",
			CVSS:    8.1,
			References: []string{
				"https://cwe.mitre.org/data/definitions/1321.html",
			},
			Remediation: "Use Object.create(null) for dictionaries. Validate keys against a blocklist. Use lodash's _.merge() which has prototype pollution protection.",
		},

		// A05:2025 - SQL injection (Node.js)
		{
			ID:          "JS-006",
			Language:    config.LangJavaScript,
			Severity:    config.SeverityHigh,
			Title:       "SQL Injection in Node.js",
			Description: "String concatenation in SQL queries allows SQL Injection attacks.",
			Pattern:     mustCompile(`(?i)(query|execute)\s*\(\s*["'\x60].*\+\s*(req\.|user|input|param)`),
			OWASP:       config.OWASP_A05_Injection,
			CWE:         "CWE-89",
			CVSS:        9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/89.html",
			},
			Remediation: "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId]). Use an ORM like Prisma or Sequelize.",
		},

		// A02:2025 - CORS wildcard
		{
			ID:       "JS-007",
			Language: config.LangJavaScript,
			Severity: config.SeverityMedium,
			Title:    "CORS wildcard origin (Express)",
			Description: "Allowing all origins via CORS wildcard exposes your API to cross-origin requests " +
				"from any website, potentially enabling CSRF-like attacks.",
			Pattern: mustCompile(`cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration,
			CWE:     "CWE-942",
			CVSS:    6.5,
			References: []string{
				"https://cwe.mitre.org/data/definitions/942.html",
			},
			Remediation: "Specify exact allowed origins: cors({ origin: ['https://yourapp.com'] }). Use environment-specific configuration.",
		},

		// A07:2025 - JWT verification skip
		{
			ID:       "JS-008",
			Language: config.LangJavaScript,
			Severity: config.SeverityCritical,
			Title:    "JWT signature verification disabled",
			Description: "Setting algorithms: ['none'] or ignoreExpiration: true in JWT allows " +
				"attackers to forge authentication tokens.",
			Pattern: mustCompile(`(?i)(ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[.*none)`),
			OWASP:   config.OWASP_A07_AuthenticationFailures,
			CWE:     "CWE-347",
			CVSS:    9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/347.html",
			},
			Remediation: "Always verify JWT expiration and use explicit algorithms: jwt.verify(token, secret, { algorithms: ['HS256'] })",
		},

		// A08:2025 - Insecure deserialization (serialize-javascript, node-serialize)
		{
			ID:       "JS-009",
			Language: config.LangJavaScript,
			Severity: config.SeverityCritical,
			Title:    "Insecure deserialization (node-serialize)",
			Description: "node-serialize's unserialize() can execute arbitrary code if the serialized " +
				"data contains a JavaScript function (IIFE).",
			Pattern: mustCompile(`(?i)(unserialize|deserialize)\s*\(`),
			OWASP:   config.OWASP_A08_SoftwareDataIntegrityFailures,
			CWE:     "CWE-502",
			CVSS:    9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/502.html",
			},
			Remediation: "Use JSON.parse() for safe deserialization. Avoid node-serialize with untrusted data. Validate all deserialized data with JSON Schema.",
		},

		// A04:2025 - Math.random() for security
		{
			ID:       "JS-010",
			Language: config.LangJavaScript,
			Severity: config.SeverityMedium,
			Title:    "Insecure random (Math.random()) for security",
			Description: "Math.random() is not cryptographically secure. Using it for tokens, " +
				"session IDs, or OTPs is predictable and exploitable.",
			Pattern: mustCompile(`Math\.random\s*\(\s*\)`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-338",
			CVSS:    5.9,
			References: []string{
				"https://cwe.mitre.org/data/definitions/338.html",
			},
			Remediation: "Use crypto.randomBytes() (Node.js) or window.crypto.getRandomValues() (browser) for security-sensitive randomness.",
		},

		// JS-011 re-implemented as a FILE-SCOPED check: fire once per file that
		// creates an Express app but never references Helmet. Far more precise
		// than the old per-line rule (which fired on every express() call, 652×
		// on the Express test suite). LOW confidence — Helmet may be applied in
		// a separate module, so this is a review hint, not a definitive finding.
		{
			ID:              "JS-011",
			Language:        config.LangJavaScript,
			Severity:        config.SeverityLow,
			Title:           "Express app without Helmet (security headers)",
			Description:     "This file creates an Express app but does not reference Helmet, so security headers (CSP, HSTS, X-Frame-Options) may be unset.",
			FileScoped:      true,
			Pattern:         mustCompile(`(?i)\bexpress\s*\(\s*\)`),
			RequiredPattern: mustCompile(`(?i)helmet`),
			OWASP:           config.OWASP_A02_SecurityMisconfiguration,
			CWE:             "CWE-693",
			CVSS:            3.1,
			References:      []string{"https://helmetjs.github.io/", "https://cwe.mitre.org/data/definitions/693.html"},
			Remediation:     "If this app serves browsers, add Helmet: const helmet = require('helmet'); app.use(helmet());",
		},

		// A01:2025 - Path traversal (Node.js)
		{
			ID:       "JS-012",
			Language: config.LangJavaScript,
			Severity: config.SeverityHigh,
			Title:    "Path traversal via user-controlled file path",
			Description: "Reading or writing files with user-controlled paths allows attackers to " +
				"access files outside the intended directory.",
			Pattern: mustCompile(`(?i)(fs\.(readFile|writeFile|readFileSync|createReadStream))\s*\(.*req\.(params|query|body)`),
			OWASP:   config.OWASP_A01_BrokenAccessControl,
			CWE:     "CWE-22",
			CVSS:    8.6,
			References: []string{
				"https://cwe.mitre.org/data/definitions/22.html",
			},
			Remediation: "Use path.resolve() and verify the result starts with the allowed base directory: if (!resolved.startsWith(baseDir)) throw new Error('Access denied')",
		},

		// A09:2025 - console.log with sensitive data
		{
			ID:       "JS-013",
			Language: config.LangJavaScript,
			Severity: config.SeverityLow,
			Title:    "Potential sensitive data in console.log",
			Description: "Logging passwords, tokens or sensitive data to the console creates exposure " +
				"risk through log aggregation systems.",
			Pattern: mustCompile(`(?i)console\.(log|error|info|debug)\s*\(.*(?:password|token|secret|credential)`),
			OWASP:   config.OWASP_A09_SecurityLoggingAlertingFailures,
			CWE:     "CWE-532",
			CVSS:    5.5,
			References: []string{
				"https://cwe.mitre.org/data/definitions/532.html",
			},
			Remediation: "Remove sensitive data from logs. Use structured logging with field-level masking. Implement a centralized logging strategy.",
		},

		// A10:2025 - Unhandled promise rejection.
		// Go RE2 has no negative lookahead, so we detect `.then(` with Pattern
		// and suppress when `.catch(` is present on the same line via AntiPattern.
		{
			ID:       "JS-014",
			Language: config.LangJavaScript,
			Severity: config.SeverityLow,
			Title:    "Unhandled promise rejection",
			Description: "Promise chains without .catch() or async functions without try/catch can " +
				"cause unexpected application behavior and hide security errors.",
			Pattern:     mustCompile(`\.then\s*\(`),
			AntiPattern: mustCompile(`\.catch\s*\(`),
			OWASP:       config.OWASP_A10_MishandlingExceptionalConditions,
			CWE:         "CWE-390",
			CVSS:        3.7,
			References: []string{
				"https://cwe.mitre.org/data/definitions/390.html",
			},
			Remediation: "Always add .catch() to promise chains. Use async/await with try/catch. Register process.on('unhandledRejection') as a safety net.",
		},

		// A05:2025 - Regular expression DoS (ReDoS)
		{
			ID:       "JS-015",
			Language: config.LangJavaScript,
			Severity: config.SeverityMedium,
			Title:    "Potential ReDoS - catastrophic backtracking regex",
			Description: "Regular expressions with nested quantifiers can cause exponential backtracking, " +
				"enabling Denial of Service with crafted input.",
			Pattern: mustCompile(`new RegExp\s*\(`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-1333",
			CVSS:    5.9,
			References: []string{
				"https://cwe.mitre.org/data/definitions/1333.html",
				"https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
			},
			Remediation: "Test regexes with safe-regex or redos tools. Set timeouts on regex operations. Use non-backtracking regex engines where possible.",
		},

		// JS-016 re-implemented as a FILE-SCOPED check: fire once per file that
		// defines state-changing routes (app.post/put/delete/patch) but never
		// references a CSRF defense (csurf/csrf token or SameSite cookies). LOW
		// confidence — token-authenticated APIs need no CSRF token, and the
		// defense may live in a shared middleware module.
		{
			ID:              "JS-016",
			Language:        config.LangJavaScript,
			Severity:        config.SeverityLow,
			Title:           "State-changing routes without CSRF defense",
			Description:     "This file defines POST/PUT/DELETE/PATCH routes but references no CSRF protection (csurf or SameSite cookies).",
			FileScoped:      true,
			Pattern:         mustCompile(`(?i)app\.(post|put|delete|patch)\s*\(`),
			RequiredPattern: mustCompile(`(?i)csrf|csurf|samesite`),
			OWASP:           config.OWASP_A01_BrokenAccessControl,
			CWE:             "CWE-352",
			CVSS:            4.3,
			References:      []string{"https://cwe.mitre.org/data/definitions/352.html"},
			Remediation:     "Use csurf middleware or SameSite=Strict cookies; for token-auth APIs, verify Origin/Referer.",
		},
	}
}
