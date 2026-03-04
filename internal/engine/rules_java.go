package engine

import "github.com/drogonsec/drogonsec/internal/config"

func javaRules() []Rule {
	return []Rule{
		// A05:2025 - SQL Injection
		{
			ID:       "JAVA-001",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "SQL Injection via string concatenation",
			Description: "Building SQL queries with string concatenation allows attackers to manipulate " +
				"database queries and access unauthorized data.",
			Pattern: mustCompile(`(?i)(Statement|createStatement|prepareStatement)\s*.*\+\s*(request|user|input|param)`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-89",
			CVSS:    9.8,
			References: []string{
				"https://owasp.org/Top10/2025/A05_2025-Injection/",
				"https://cwe.mitre.org/data/definitions/89.html",
			},
			Remediation: "Use PreparedStatement with parameterized queries: PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setInt(1, userId);",
		},

		// A05:2025 - Command Injection
		{
			ID:       "JAVA-002",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Command Injection via Runtime.exec()",
			Description: "Executing system commands with user-controlled input enables arbitrary " +
				"command execution on the server.",
			Pattern: mustCompile(`Runtime\.getRuntime\(\)\.exec\s*\(`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-78",
			CVSS:    9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/78.html",
			},
			Remediation: "Avoid Runtime.exec() with user input. Use ProcessBuilder with an explicit command list and validate all inputs against a strict allowlist.",
		},

		// A04:2025 - Hardcoded password
		{
			ID:       "JAVA-003",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Hardcoded password or secret",
			Description: "Credentials hardcoded in Java source code are easily discovered and cannot " +
				"be rotated without a code deployment.",
			Pattern: mustCompile(`(?i)(password|passwd|secret|apiKey|api_key)\s*=\s*"[^"]{4,}"`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-259",
			CVSS:    8.0,
			References: []string{
				"https://cwe.mitre.org/data/definitions/259.html",
			},
			Remediation: "Use environment variables or a secrets manager. Spring Boot: @Value(\"${app.secret}\") or Spring Cloud Vault.",
		},

		// A04:2025 - MD5 usage
		{
			ID:       "JAVA-004",
			Language: config.LangJava,
			Severity: config.SeverityMedium,
			Title:    "Use of MD5 weak hash algorithm",
			Description: "MD5 is cryptographically broken. Collisions can be computed efficiently, " +
				"making it unsuitable for security-sensitive operations.",
			Pattern: mustCompile(`MessageDigest\.getInstance\s*\(\s*"MD5"`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-327",
			CVSS:    5.9,
			References: []string{
				"https://cwe.mitre.org/data/definitions/327.html",
			},
			Remediation: "Use SHA-256: MessageDigest.getInstance(\"SHA-256\"). For passwords, use BCrypt from Spring Security.",
		},

		// A04:2025 - SHA1 usage
		{
			ID:       "JAVA-005",
			Language: config.LangJava,
			Severity: config.SeverityMedium,
			Title:    "Use of SHA1 weak hash algorithm",
			Description: "SHA-1 is vulnerable to collision attacks and should not be used for " +
				"security-critical operations.",
			Pattern: mustCompile(`MessageDigest\.getInstance\s*\(\s*"SHA-1"`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-327",
			CVSS:    5.9,
			References: []string{
				"https://cwe.mitre.org/data/definitions/327.html",
			},
			Remediation: "Use SHA-256 or SHA-3: MessageDigest.getInstance(\"SHA-256\")",
		},

		// A08:2025 - Insecure deserialization
		{
			ID:       "JAVA-006",
			Language: config.LangJava,
			Severity: config.SeverityCritical,
			Title:    "Insecure Java deserialization (ObjectInputStream)",
			Description: "Java's native deserialization has been a source of critical RCE vulnerabilities. " +
				"Deserializing untrusted data with ObjectInputStream is extremely dangerous.",
			Pattern: mustCompile(`ObjectInputStream\s*\(`),
			OWASP:   config.OWASP_A08_SoftwareDataIntegrityFailures,
			CWE:     "CWE-502",
			CVSS:    9.8,
			References: []string{
				"https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/",
				"https://cwe.mitre.org/data/definitions/502.html",
			},
			Remediation: "Avoid Java native serialization. Use JSON (Jackson, Gson), Protocol Buffers, or XML. If deserialization is required, use SerialKiller or similar input validation libraries.",
		},

		// A02:2025 - XML External Entity (XXE)
		{
			ID:       "JAVA-007",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "XML External Entity (XXE) vulnerability",
			Description: "XML parsers with external entity processing enabled allow attackers to " +
				"read local files, perform SSRF, or cause DoS.",
			Pattern: mustCompile(`(?i)(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(\s*\)`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration,
			CWE:     "CWE-611",
			CVSS:    8.6,
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
				"https://cwe.mitre.org/data/definitions/611.html",
			},
			Remediation: "Disable external entity processing: factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);",
		},

		// A01:2025 - Path traversal
		{
			ID:       "JAVA-008",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Path traversal vulnerability",
			Description: "Constructing file paths with unvalidated user input allows attackers to " +
				"read arbitrary files from the filesystem.",
			Pattern: mustCompile(`new\s+File\s*\(.*\+\s*(request|user|param|input)`),
			OWASP:   config.OWASP_A01_BrokenAccessControl,
			CWE:     "CWE-22",
			CVSS:    8.6,
			References: []string{
				"https://cwe.mitre.org/data/definitions/22.html",
			},
			Remediation: "Use Paths.get(baseDir).resolve(userInput).normalize() and verify the result starts with the expected base directory.",
		},

		// A07:2025 - Weak cryptography for password
		{
			ID:       "JAVA-009",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Insecure password storage (not using BCrypt/Argon2)",
			Description: "Storing passwords without a proper password hashing algorithm (bcrypt, argon2, scrypt) " +
				"makes them vulnerable to offline cracking attacks.",
			Pattern: mustCompile(`(?i)(password|passwd)\.getBytes\s*\(`),
			OWASP:   config.OWASP_A07_AuthenticationFailures,
			CWE:     "CWE-916",
			CVSS:    8.1,
			References: []string{
				"https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
				"https://cwe.mitre.org/data/definitions/916.html",
			},
			Remediation: "Use Spring Security BCryptPasswordEncoder or Argon2PasswordEncoder for password hashing.",
		},

		// A05:2025 - LDAP Injection
		{
			ID:       "JAVA-010",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "LDAP Injection vulnerability",
			Description: "Constructing LDAP queries with unsanitized user input allows attackers to " +
				"bypass authentication or exfiltrate directory data.",
			Pattern: mustCompile(`(?i)(DirContext|search|NamingEnumeration).*\+\s*(user|input|param|request)`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-90",
			CVSS:    8.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/90.html",
			},
			Remediation: "Escape all user input using LDAP encoding: LdapEncoder.filterEncode(userInput). Use Spring Security's LDAP integration.",
		},

		// A02:2025 - SSL verification disabled
		{
			ID:       "JAVA-011",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "SSL/TLS certificate verification disabled",
			Description: "Disabling SSL certificate validation exposes all HTTPS connections to " +
				"man-in-the-middle attacks.",
			Pattern: mustCompile(`(?i)(TrustAllCerts|AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier)`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-295",
			CVSS:    7.4,
			References: []string{
				"https://cwe.mitre.org/data/definitions/295.html",
			},
			Remediation: "Use the default SSL context which validates certificates. If needed, configure a proper TrustStore with your CA certificates.",
		},

		// A05:2025 - XSS via response.getWriter
		{
			ID:       "JAVA-012",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Potential Cross-Site Scripting (XSS)",
			Description: "Writing user-controlled data directly to HTTP response without encoding " +
				"enables Cross-Site Scripting attacks.",
			Pattern: mustCompile(`(?i)response\.getWriter\(\)\.write\s*\(.*request\.(getParameter|getAttribute)`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-79",
			CVSS:    7.4,
			References: []string{
				"https://cwe.mitre.org/data/definitions/79.html",
				"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
			},
			Remediation: "HTML-encode output: ESAPI.encoder().encodeForHTML(userInput) or use OWASP Java HTML Sanitizer.",
		},

		// A09:2025 - Log injection
		{
			ID:       "JAVA-013",
			Language: config.LangJava,
			Severity: config.SeverityMedium,
			Title:    "Log injection / Log forging",
			Description: "Logging user-controlled input without sanitization allows log injection attacks, " +
				"potentially hiding malicious activity or poisoning log analysis.",
			Pattern: mustCompile(`(?i)(log|logger)\.(debug|info|warn|error|trace)\s*\(.*request\.(getParameter|getHeader)`),
			OWASP:   config.OWASP_A09_SecurityLoggingAlertingFailures,
			CWE:     "CWE-117",
			CVSS:    5.3,
			References: []string{
				"https://cwe.mitre.org/data/definitions/117.html",
			},
			Remediation: "Sanitize user input before logging. Remove or encode newline characters: input.replaceAll(\"[\\r\\n]\", \"_\")",
		},

		// A06:2025 - Spring actuator exposed
		{
			ID:       "JAVA-014",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Spring Actuator endpoints exposed",
			Description: "Exposing all Spring Actuator endpoints without authentication gives " +
				"attackers access to sensitive application internals.",
			Pattern: mustCompile(`(?i)management\.endpoints\.web\.exposure\.include\s*=\s*\*`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration,
			CWE:     "CWE-548",
			CVSS:    7.5,
			References: []string{
				"https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
				"https://cwe.mitre.org/data/definitions/548.html",
			},
			Remediation: "Expose only needed endpoints and secure them: management.endpoints.web.exposure.include=health,info and add security configuration.",
		},

		// A10:2025 - Empty catch block
		{
			ID:       "JAVA-015",
			Language: config.LangJava,
			Severity: config.SeverityLow,
			Title:    "Empty catch block suppresses exceptions",
			Description: "Catching and ignoring exceptions hides errors that may have security " +
				"implications, making incident response impossible.",
			Pattern: mustCompile(`catch\s*\([^)]+\)\s*\{\s*\}`),
			OWASP:   config.OWASP_A10_MishandlingExceptionalConditions,
			CWE:     "CWE-390",
			CVSS:    3.7,
			References: []string{
				"https://cwe.mitre.org/data/definitions/390.html",
			},
			Remediation: "Always log exceptions with context. Implement proper error handling strategies. Never silently catch exceptions.",
		},

		// A04:2025 - DES/3DES weak encryption
		{
			ID:       "JAVA-016",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Use of weak DES/3DES encryption algorithm",
			Description: "DES and 3DES are obsolete encryption algorithms vulnerable to brute force " +
				"and meet-in-the-middle attacks.",
			Pattern: mustCompile(`Cipher\.getInstance\s*\(\s*"(DES|DESede|3DES)`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-327",
			CVSS:    7.5,
			References: []string{
				"https://cwe.mitre.org/data/definitions/327.html",
			},
			Remediation: "Use AES-256-GCM: Cipher.getInstance(\"AES/GCM/NoPadding\")",
		},

		// A04:2025 - ECB mode
		{
			ID:       "JAVA-017",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "Use of AES in ECB mode (insecure)",
			Description: "AES/ECB mode is deterministic and does not provide semantic security. " +
				"It reveals patterns in encrypted data.",
			Pattern: mustCompile(`Cipher\.getInstance\s*\(\s*"AES/ECB`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-327",
			CVSS:    7.5,
			References: []string{
				"https://cwe.mitre.org/data/definitions/327.html",
			},
			Remediation: "Use AES/GCM/NoPadding for authenticated encryption or AES/CBC/PKCS5Padding with a random IV.",
		},

		// A01:2025 - Open redirect
		{
			ID:       "JAVA-018",
			Language: config.LangJava,
			Severity: config.SeverityMedium,
			Title:    "Open redirect vulnerability",
			Description: "Redirecting to URLs from user input without validation enables phishing attacks " +
				"by using your trusted domain to redirect to malicious sites.",
			Pattern: mustCompile(`(?i)response\.sendRedirect\s*\(.*request\.(getParameter|getAttribute)`),
			OWASP:   config.OWASP_A01_BrokenAccessControl,
			CWE:     "CWE-601",
			CVSS:    6.1,
			References: []string{
				"https://cwe.mitre.org/data/definitions/601.html",
			},
			Remediation: "Validate redirect URLs against an allowlist of permitted destinations. Reject external URLs or use relative paths only.",
		},

		// A07:2025 - Insecure session configuration
		{
			ID:       "JAVA-019",
			Language: config.LangJava,
			Severity: config.SeverityMedium,
			Title:    "Insecure cookie configuration (missing HttpOnly/Secure)",
			Description: "Session cookies without HttpOnly flag can be accessed via JavaScript (XSS risk). " +
				"Cookies without Secure flag are transmitted over HTTP.",
			Pattern: mustCompile(`new\s+Cookie\s*\(`),
			OWASP:   config.OWASP_A07_AuthenticationFailures,
			CWE:     "CWE-614",
			CVSS:    5.9,
			References: []string{
				"https://cwe.mitre.org/data/definitions/614.html",
			},
			Remediation: "Always set: cookie.setHttpOnly(true); cookie.setSecure(true); cookie.setSameSite(\"Strict\");",
		},

		// A05:2025 - XPath injection
		{
			ID:       "JAVA-020",
			Language: config.LangJava,
			Severity: config.SeverityHigh,
			Title:    "XPath Injection vulnerability",
			Description: "Building XPath expressions with user input allows attackers to bypass " +
				"authentication or extract arbitrary XML data.",
			Pattern: mustCompile(`(?i)(xpath\.evaluate|compile\s*\().*\+\s*(user|input|param|request)`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-643",
			CVSS:    8.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/643.html",
			},
			Remediation: "Use parameterized XPath with XPathVariableResolver to separate the query from data.",
		},
	}
}
