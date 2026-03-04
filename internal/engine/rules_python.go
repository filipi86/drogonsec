package engine

import "github.com/drogonsec/drogonsec/internal/config"

func pythonRules() []Rule {
	return []Rule{
		// A05:2025 - SQL Injection
		{
			ID:       "PY-001",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "SQL Injection via string formatting",
			Description: "Direct string interpolation in SQL queries allows SQL Injection attacks. " +
				"Attackers can manipulate queries to access or modify unauthorized data.",
			Pattern: mustCompile(`(?i)(execute|cursor\.execute|db\.execute)\s*\(.*(%s|\.format\(|f["'].*\{|["']\s*\+)`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-89",
			CVSS:    9.8,
			References: []string{
				"https://owasp.org/Top10/2025/A05_2025-Injection/",
				"https://cwe.mitre.org/data/definitions/89.html",
			},
			Remediation: "Use parameterized queries or prepared statements. Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
		},

		// A05:2025 - Command Injection
		{
			ID:       "PY-002",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "Command Injection via os.system or subprocess with shell=True",
			Description: "Using os.system() or subprocess with shell=True and user input allows " +
				"arbitrary command execution.",
			Pattern: mustCompile(`(?i)(os\.system|subprocess\.(call|run|Popen))\s*\(.*shell\s*=\s*True`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-78",
			CVSS:    9.8,
			References: []string{
				"https://owasp.org/Top10/2025/A05_2025-Injection/",
				"https://cwe.mitre.org/data/definitions/78.html",
			},
			Remediation: "Avoid shell=True. Use subprocess.run(['cmd', 'arg']) with a list of arguments.",
		},

		// A04:2025 - Hardcoded secret / password
		{
			ID:       "PY-003",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "Hardcoded password or secret",
			Description: "Hardcoded credentials in source code expose sensitive data and are " +
				"easily discovered through code review or repository searches.",
			Pattern: mustCompile(`(?i)(password|passwd|secret|api_key|apikey|token)\s*=\s*["'][^"']{4,}["']`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-259",
			CVSS:    8.0,
			References: []string{
				"https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
				"https://cwe.mitre.org/data/definitions/259.html",
			},
			Remediation: "Use environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). Never commit credentials to source control.",
		},

		// A04:2025 - Weak hash algorithm (MD5)
		{
			ID:       "PY-004",
			Language: config.LangPython,
			Severity: config.SeverityMedium,
			Title:    "Use of MD5 weak hash algorithm",
			Description: "MD5 is cryptographically broken and should not be used for " +
				"security-sensitive operations like password hashing or integrity checks.",
			Pattern: mustCompile(`(?i)hashlib\.md5\s*\(`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-327",
			CVSS:    5.9,
			References: []string{
				"https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
				"https://cwe.mitre.org/data/definitions/327.html",
			},
			Remediation: "Use hashlib.sha256() or hashlib.sha3_256() for non-password hashing. For passwords, use bcrypt, argon2, or scrypt.",
		},

		// A04:2025 - Weak hash algorithm (SHA1)
		{
			ID:          "PY-005",
			Language:    config.LangPython,
			Severity:    config.SeverityMedium,
			Title:       "Use of SHA1 weak hash algorithm",
			Description: "SHA1 is considered weak for security purposes and collision attacks are practical.",
			Pattern:     mustCompile(`(?i)hashlib\.sha1\s*\(`),
			OWASP:       config.OWASP_A04_CryptographicFailures,
			CWE:         "CWE-327",
			CVSS:        5.9,
			References: []string{
				"https://cwe.mitre.org/data/definitions/327.html",
			},
			Remediation: "Replace with hashlib.sha256() or stronger algorithms.",
		},

		// A05:2025 - XSS via render_template_string
		{
			ID:       "PY-006",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "Server-Side Template Injection (SSTI) via render_template_string",
			Description: "Rendering user-controlled input through render_template_string can lead to " +
				"template injection, allowing arbitrary code execution.",
			Pattern: mustCompile(`render_template_string\s*\(`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-94",
			CVSS:    9.0,
			References: []string{
				"https://owasp.org/Top10/2025/A05_2025-Injection/",
			},
			Remediation: "Use render_template() with static template files. Never pass user input directly to render_template_string().",
		},

		// A01:2025 - Insecure deserialization (pickle)
		{
			ID:       "PY-007",
			Language: config.LangPython,
			Severity: config.SeverityCritical,
			Title:    "Insecure deserialization with pickle",
			Description: "Python's pickle module can execute arbitrary code during deserialization. " +
				"Never deserialize data from untrusted sources using pickle.",
			Pattern: mustCompile(`(?i)pickle\.(loads|load)\s*\(`),
			OWASP:   config.OWASP_A08_SoftwareDataIntegrityFailures,
			CWE:     "CWE-502",
			CVSS:    9.8,
			References: []string{
				"https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/",
				"https://cwe.mitre.org/data/definitions/502.html",
			},
			Remediation: "Use JSON or other safe serialization formats. If pickle is required, validate data integrity with HMAC before deserializing.",
		},

		// A02:2025 - Debug mode enabled
		{
			ID:       "PY-008",
			Language: config.LangPython,
			Severity: config.SeverityMedium,
			Title:    "Flask debug mode enabled",
			Description: "Running Flask with debug=True in production exposes an interactive debugger " +
				"and allows arbitrary Python code execution.",
			Pattern: mustCompile(`(?i)app\.run\s*\(.*debug\s*=\s*True`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration,
			CWE:     "CWE-94",
			CVSS:    7.5,
			References: []string{
				"https://flask.palletsprojects.com/en/stable/deploying/",
			},
			Remediation: "Set debug=False or use environment variables: app.run(debug=os.environ.get('FLASK_DEBUG', False))",
		},

		// A05:2025 - eval() with user input
		{
			ID:       "PY-009",
			Language: config.LangPython,
			Severity: config.SeverityCritical,
			Title:    "Code injection via eval()",
			Description: "eval() executes arbitrary Python code. Using user-controlled input with eval() " +
				"allows complete system compromise.",
			Pattern: mustCompile(`(?i)\beval\s*\(`),
			OWASP:   config.OWASP_A05_Injection,
			CWE:     "CWE-95",
			CVSS:    9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/95.html",
			},
			Remediation: "Avoid eval() entirely. Use ast.literal_eval() for safe evaluation of literals, or refactor logic to avoid dynamic code execution.",
		},

		// A06:2025 - SSRF via requests
		{
			ID:       "PY-010",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "Potential SSRF - requests with user-controlled URL",
			Description: "Making HTTP requests with user-controlled URLs can lead to Server-Side Request " +
				"Forgery (SSRF), allowing attackers to reach internal services.",
			Pattern: mustCompile(`requests\.(get|post|put|delete|patch|head)\s*\(\s*(request\.|user_input|url|target)`),
			OWASP:   config.OWASP_A01_BrokenAccessControl,
			CWE:     "CWE-918",
			CVSS:    8.6,
			References: []string{
				"https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
				"https://cwe.mitre.org/data/definitions/918.html",
			},
			Remediation: "Validate and allowlist URLs. Use a URL parser to verify scheme, host, and path. Block access to private IP ranges.",
		},

		// A09:2025 - Logging sensitive data
		{
			ID:       "PY-011",
			Language: config.LangPython,
			Severity: config.SeverityMedium,
			Title:    "Potential logging of sensitive information",
			Description: "Logging passwords, tokens, or other sensitive data creates exposure risks " +
				"through log files, monitoring systems, and SIEM tools.",
			Pattern: mustCompile(`(?i)(logging\.|logger\.)(debug|info|warning|error|critical)\s*\(.*(?:password|token|secret|credential|api_key)`),
			OWASP:   config.OWASP_A09_SecurityLoggingAlertingFailures,
			CWE:     "CWE-532",
			CVSS:    5.5,
			References: []string{
				"https://cwe.mitre.org/data/definitions/532.html",
			},
			Remediation: "Never log sensitive values. Mask or redact credentials before logging. Use structured logging with field-level sensitivity controls.",
		},

		// A07:2025 - Weak password length requirement
		{
			ID:       "PY-012",
			Language: config.LangPython,
			Severity: config.SeverityLow,
			Title:    "Weak minimum password length",
			Description: "Passwords shorter than 8 characters are easily brute-forced. " +
				"Modern security standards recommend at least 12 characters.",
			Pattern: mustCompile(`(?i)len\(password\)\s*[<>]\s*[1-7]\b`),
			OWASP:   config.OWASP_A07_AuthenticationFailures,
			CWE:     "CWE-521",
			CVSS:    4.3,
			References: []string{
				"https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
			},
			Remediation: "Enforce minimum password length of 12+ characters. Follow NIST SP 800-63B guidelines.",
		},

		// A10:2025 - Bare except
		{
			ID:       "PY-013",
			Language: config.LangPython,
			Severity: config.SeverityLow,
			Title:    "Bare except clause swallows all exceptions",
			Description: "Catching all exceptions without logging or handling them appropriately " +
				"hides security-relevant errors and makes debugging impossible.",
			Pattern: mustCompile(`except:\s*$`),
			OWASP:   config.OWASP_A10_MishandlingExceptionalConditions,
			CWE:     "CWE-390",
			CVSS:    3.7,
			References: []string{
				"https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
				"https://cwe.mitre.org/data/definitions/390.html",
			},
			Remediation: "Catch specific exceptions. Log all unexpected exceptions. Never silently swallow errors.",
		},

		// A04:2025 - Insecure random
		{
			ID:       "PY-014",
			Language: config.LangPython,
			Severity: config.SeverityMedium,
			Title:    "Use of insecure random number generator",
			Description: "Python's random module is not cryptographically secure and should not be " +
				"used for security-sensitive operations like token generation.",
			Pattern: mustCompile(`(?i)\brandom\.(random|randint|choice|randrange|shuffle)\s*\(`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-338",
			CVSS:    5.9,
			References: []string{
				"https://cwe.mitre.org/data/definitions/338.html",
			},
			Remediation: "Use the secrets module for security-sensitive operations: secrets.token_hex(), secrets.token_urlsafe()",
		},

		// A04:2025 - SSL/TLS verification disabled
		{
			ID:       "PY-015",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "SSL/TLS certificate verification disabled",
			Description: "Disabling SSL certificate verification exposes the application to " +
				"man-in-the-middle attacks.",
			Pattern: mustCompile(`verify\s*=\s*False`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-295",
			CVSS:    7.4,
			References: []string{
				"https://cwe.mitre.org/data/definitions/295.html",
			},
			Remediation: "Never disable SSL verification in production. If using self-signed certificates, provide the CA bundle: verify='/path/to/ca-bundle.crt'",
		},

		// A01:2025 - Path traversal
		{
			ID:       "PY-016",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "Path traversal vulnerability",
			Description: "Constructing file paths with unsanitized user input allows attackers " +
				"to read or write files outside the intended directory.",
			Pattern: mustCompile(`open\s*\(.*\+`),
			OWASP:   config.OWASP_A01_BrokenAccessControl,
			CWE:     "CWE-22",
			CVSS:    8.6,
			References: []string{
				"https://cwe.mitre.org/data/definitions/22.html",
			},
			Remediation: "Use os.path.realpath() and validate the result is within the allowed directory. Use pathlib for safe path operations.",
		},

		// A02:2025 - CORS wildcard
		{
			ID:       "PY-017",
			Language: config.LangPython,
			Severity: config.SeverityMedium,
			Title:    "CORS wildcard origin configured",
			Description: "Allowing all origins via CORS wildcard (*) exposes APIs to cross-origin " +
				"attacks from any website.",
			Pattern: mustCompile(`(?i)(CORS_ORIGINS|origins|allow_origins)\s*=\s*[\["]?\*`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration,
			CWE:     "CWE-942",
			CVSS:    6.5,
			References: []string{
				"https://cwe.mitre.org/data/definitions/942.html",
			},
			Remediation: "Specify exact allowed origins. Use environment-specific CORS configuration.",
		},

		// A06:2025 - Insecure direct object reference
		{
			ID:       "PY-018",
			Language: config.LangPython,
			Severity: config.SeverityMedium,
			Title:    "Potential Insecure Direct Object Reference (IDOR)",
			Description: "Directly using user-provided IDs in queries without authorization checks " +
				"may expose other users' data.",
			Pattern: mustCompile(`(?i)(request\.(args|form|json|params)\.get\(.*id)\s*[^)]*\)`),
			OWASP:   config.OWASP_A01_BrokenAccessControl,
			CWE:     "CWE-639",
			CVSS:    6.5,
			References: []string{
				"https://cwe.mitre.org/data/definitions/639.html",
			},
			Remediation: "Always verify that the authenticated user has permission to access the requested resource. Use indirect object references.",
		},

		// A08:2025 - PyYAML load (unsafe)
		{
			ID:       "PY-019",
			Language: config.LangPython,
			Severity: config.SeverityCritical,
			Title:    "Unsafe YAML deserialization with yaml.load()",
			Description: "yaml.load() without the Loader parameter can execute arbitrary Python code. " +
				"This is a critical vulnerability when processing untrusted YAML.",
			Pattern: mustCompile(`yaml\.load\s*\([^)]*\)`),
			OWASP:   config.OWASP_A08_SoftwareDataIntegrityFailures,
			CWE:     "CWE-502",
			CVSS:    9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/502.html",
				"https://pyyaml.org/wiki/PyYAMLDocumentation",
			},
			Remediation: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead.",
		},

		// A04:2025 - Hardcoded private key
		{
			ID:       "PY-020",
			Language: config.LangPython,
			Severity: config.SeverityCritical,
			Title:    "Hardcoded RSA/private key in source",
			Description: "Private cryptographic keys embedded in source code compromise the entire " +
				"security system and cannot be rotated without code changes.",
			Pattern: mustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			OWASP:   config.OWASP_A04_CryptographicFailures,
			CWE:     "CWE-321",
			CVSS:    9.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/321.html",
			},
			Remediation: "Remove private keys from source code immediately. Store keys in environment variables, secrets managers, or HSMs. Rotate all exposed keys.",
		},

		// A07:2025 - JWT none algorithm
		{
			ID:       "PY-021",
			Language: config.LangPython,
			Severity: config.SeverityCritical,
			Title:    "JWT 'none' algorithm accepted",
			Description: "Accepting the 'none' algorithm in JWT allows attackers to forge tokens " +
				"without a valid signature.",
			Pattern: mustCompile(`(?i)algorithms\s*=\s*\[.*["']none["']`),
			OWASP:   config.OWASP_A07_AuthenticationFailures,
			CWE:     "CWE-347",
			CVSS:    9.8,
			References: []string{
				"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
				"https://cwe.mitre.org/data/definitions/347.html",
			},
			Remediation: "Explicitly specify allowed algorithms and never include 'none'. Example: algorithms=['HS256', 'RS256']",
		},

		// A01:2025 - Unrestricted file upload
		{
			ID:       "PY-022",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "Unrestricted file upload",
			Description: "Saving uploaded files without validating type and content allows " +
				"attackers to upload malicious files including web shells.",
			Pattern: mustCompile(`(?i)(request\.files|upload)\[.*\]\.save\s*\(`),
			OWASP:   config.OWASP_A01_BrokenAccessControl,
			CWE:     "CWE-434",
			CVSS:    8.8,
			References: []string{
				"https://cwe.mitre.org/data/definitions/434.html",
			},
			Remediation: "Validate file type by content (not extension), limit file size, store outside web root, use a CDN or object storage for uploads.",
		},

		// A02:2025 - SECRET_KEY default/weak
		{
			ID:       "PY-023",
			Language: config.LangPython,
			Severity: config.SeverityHigh,
			Title:    "Weak or default SECRET_KEY",
			Description: "A weak or default SECRET_KEY compromises all session tokens, CSRF tokens, " +
				"and other cryptographic operations in Django/Flask.",
			Pattern: mustCompile(`SECRET_KEY\s*=\s*["'](secret|changeme|development|test|default|django-insecure)`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration,
			CWE:     "CWE-1392",
			CVSS:    9.1,
			References: []string{
				"https://docs.djangoproject.com/en/stable/ref/settings/#secret-key",
			},
			Remediation: "Generate a strong random SECRET_KEY: python -c \"import secrets; print(secrets.token_hex(50))\" and store in environment variable.",
		},

		// A10:2025 - Missing error handling
		{
			ID:       "PY-024",
			Language: config.LangPython,
			Severity: config.SeverityLow,
			Title:    "Exception silently suppressed (pass in except)",
			Description: "Silently ignoring exceptions hides security-relevant errors and makes " +
				"incident detection impossible.",
			Pattern: mustCompile(`except\s+\w.*:\s*\n\s*pass`),
			OWASP:   config.OWASP_A10_MishandlingExceptionalConditions,
			CWE:     "CWE-390",
			CVSS:    3.7,
			References: []string{
				"https://cwe.mitre.org/data/definitions/390.html",
			},
			Remediation: "Log all exceptions with proper context. Implement alerting for security-relevant errors. Never silently pass exceptions.",
		},
	}
}
