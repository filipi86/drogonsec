package engine

import "github.com/drogonsec/drogonsec/internal/config"

func golangRules() []Rule {
	return []Rule{
		{
			ID: "GO-001", Language: config.LangGo, Severity: config.SeverityHigh,
			Title:       "SQL Injection via string formatting",
			Description: "Building SQL queries with fmt.Sprintf allows SQL injection.",
			Pattern:     mustCompile(`(?i)(db|DB)\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-89", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
			Remediation: "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = ?\", id)",
		},
		{
			ID: "GO-002", Language: config.LangGo, Severity: config.SeverityHigh,
			Title:       "Command injection via exec.Command with user input",
			Description: "Passing user input directly to exec.Command enables arbitrary command execution.",
			Pattern:     mustCompile(`exec\.Command\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-78", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
			Remediation: "Validate all command arguments. Never pass user input as command arguments. Use an allowlist of permitted commands.",
		},
		{
			ID: "GO-003", Language: config.LangGo, Severity: config.SeverityHigh,
			Title:       "Hardcoded credential in Go source",
			Description: "Hardcoded passwords and API keys in Go source expose sensitive data.",
			Pattern:     mustCompile(`(?i)(password|secret|apiKey|token)\s*:=\s*"[^"]{4,}"`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-259", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/259.html"},
			Remediation: "Use os.Getenv(\"SECRET\") or a secrets management library like Vault.",
		},
		{
			ID: "GO-004", Language: config.LangGo, Severity: config.SeverityMedium,
			Title:       "Use of MD5 weak hash",
			Description: "MD5 is cryptographically broken.",
			Pattern:     mustCompile(`(?i)md5\.New\s*\(\s*\)|md5\.Sum\s*\(`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-327", CVSS: 5.9,
			References:  []string{"https://cwe.mitre.org/data/definitions/327.html"},
			Remediation: "Use crypto/sha256 or crypto/sha3 instead.",
		},
		{
			ID: "GO-005", Language: config.LangGo, Severity: config.SeverityHigh,
			Title:       "TLS InsecureSkipVerify enabled",
			Description: "Disabling TLS verification opens connections to MITM attacks.",
			Pattern:     mustCompile(`InsecureSkipVerify\s*:\s*true`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-295", CVSS: 7.4,
			References:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
			Remediation: "Remove InsecureSkipVerify. Configure proper TLS with x509.CertPool for custom CAs.",
		},
		{
			ID: "GO-006", Language: config.LangGo, Severity: config.SeverityHigh,
			Title:       "Path traversal in file operations",
			Description: "User-controlled file paths allow reading arbitrary files.",
			Pattern:     mustCompile(`(?i)(os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\(.*\+`),
			OWASP:       config.OWASP_A01_BrokenAccessControl, CWE: "CWE-22", CVSS: 8.6,
			References:  []string{"https://cwe.mitre.org/data/definitions/22.html"},
			Remediation: "Use filepath.Clean() and verify the cleaned path starts with the allowed base directory.",
		},
		{
			ID: "GO-007", Language: config.LangGo, Severity: config.SeverityMedium,
			Title:       "Unsafe use of math/rand for security",
			Description: "math/rand is not cryptographically secure.",
			Pattern:     mustCompile(`(?i)math/rand|rand\.(Int|Intn|Float|Perm)\s*\(`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-338", CVSS: 5.9,
			References:  []string{"https://cwe.mitre.org/data/definitions/338.html"},
			Remediation: "Use crypto/rand for security-sensitive randomness.",
		},
		{
			ID: "GO-008", Language: config.LangGo, Severity: config.SeverityCritical,
			Title:       "Insecure deserialization with gob/decode",
			Description: "Decoding untrusted data with gob can be exploited.",
			Pattern:     mustCompile(`(?i)gob\.NewDecoder\s*\(`),
			OWASP:       config.OWASP_A08_SoftwareDataIntegrityFailures, CWE: "CWE-502", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/502.html"},
			Remediation: "Use JSON with strict schema validation for data from untrusted sources.",
		},
	}
}

func phpRules() []Rule {
	return []Rule{
		{
			ID: "PHP-001", Language: config.LangPHP, Severity: config.SeverityHigh,
			Title:       "SQL Injection via string concatenation",
			Description: "Concatenating user input into SQL queries allows SQL injection.",
			Pattern:     mustCompile(`(?i)(mysql_query|mysqli_query|query)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-89", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
			Remediation: "Use PDO with prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
		},
		{
			ID: "PHP-002", Language: config.LangPHP, Severity: config.SeverityCritical,
			Title:       "Remote Code Execution via eval()",
			Description: "eval() with user input allows arbitrary PHP code execution.",
			Pattern:     mustCompile(`\beval\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-95", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/95.html"},
			Remediation: "Never use eval() with user input. Refactor logic to avoid dynamic code execution.",
		},
		{
			ID: "PHP-003", Language: config.LangPHP, Severity: config.SeverityHigh,
			Title:       "Command injection via system()/exec()",
			Description: "Executing system commands with user input enables arbitrary command execution.",
			Pattern:     mustCompile(`(?i)(system|exec|shell_exec|passthru|popen)\s*\(.*\$_(GET|POST|REQUEST)`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-78", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
			Remediation: "Use escapeshellarg() on all arguments. Validate against an allowlist. Avoid system() with user input entirely.",
		},
		{
			ID: "PHP-004", Language: config.LangPHP, Severity: config.SeverityHigh,
			Title:       "Cross-Site Scripting (XSS) via echo without escaping",
			Description: "Echoing user input without HTML encoding enables XSS.",
			Pattern:     mustCompile(`(?i)(echo|print)\s+.*\$_(GET|POST|REQUEST|COOKIE)`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-79", CVSS: 7.4,
			References:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
			Remediation: "Use htmlspecialchars($input, ENT_QUOTES, 'UTF-8') before output.",
		},
		{
			ID: "PHP-005", Language: config.LangPHP, Severity: config.SeverityHigh,
			Title:       "File inclusion vulnerability (LFI/RFI)",
			Description: "Including files based on user input enables Local/Remote File Inclusion attacks.",
			Pattern:     mustCompile(`(?i)(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST)`),
			OWASP:       config.OWASP_A01_BrokenAccessControl, CWE: "CWE-98", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/98.html"},
			Remediation: "Never include files based on user input. Use a whitelist of permitted template names and map to file paths internally.",
		},
		{
			ID: "PHP-006", Language: config.LangPHP, Severity: config.SeverityHigh,
			Title:       "Hardcoded database password",
			Description: "Database credentials hardcoded in PHP source are easily discovered.",
			Pattern:     mustCompile(`(?i)(password|passwd|db_pass)\s*=\s*["'][^"']{4,}["']`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-259", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/259.html"},
			Remediation: "Use environment variables: getenv('DB_PASSWORD') or a .env file (never committed to VCS).",
		},
		{
			ID: "PHP-007", Language: config.LangPHP, Severity: config.SeverityMedium,
			Title:       "MD5 used for password hashing",
			Description: "MD5 is not suitable for password hashing - use password_hash() instead.",
			Pattern:     mustCompile(`(?i)md5\s*\(\s*\$password`),
			OWASP:       config.OWASP_A07_AuthenticationFailures, CWE: "CWE-916", CVSS: 8.1,
			References:  []string{"https://cwe.mitre.org/data/definitions/916.html"},
			Remediation: "Use password_hash($password, PASSWORD_ARGON2ID) and password_verify() for authentication.",
		},
	}
}

func kotlinRules() []Rule {
	return []Rule{
		{
			ID: "KT-001", Language: config.LangKotlin, Severity: config.SeverityHigh,
			Title:       "Hardcoded credential",
			Description: "Credentials hardcoded in Kotlin source code.",
			Pattern:     mustCompile(`(?i)(password|secret|apiKey|token)\s*=\s*"[^"]{4,}"`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-259", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/259.html"},
			Remediation: "Use Android Keystore System or environment-based configuration.",
		},
		{
			ID: "KT-002", Language: config.LangKotlin, Severity: config.SeverityHigh,
			Title:       "SQL Injection in Kotlin",
			Description: "String concatenation in Room/SQLite queries allows SQL injection.",
			Pattern:     mustCompile(`(?i)(rawQuery|execSQL)\s*\(.*\+`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-89", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
			Remediation: "Use Room query parameters: @Query(\"SELECT * FROM users WHERE id = :userId\")",
		},
		{
			ID: "KT-003", Language: config.LangKotlin, Severity: config.SeverityHigh,
			Title:       "TLS/SSL verification disabled in OkHttp",
			Description: "Disabling certificate verification enables MITM attacks.",
			Pattern:     mustCompile(`(?i)(hostnameVerifier|ALLOW_ALL|trustAllCerts|sslSocketFactory)`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-295", CVSS: 7.4,
			References:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
			Remediation: "Use the default OkHttpClient which validates SSL certificates. Implement certificate pinning for sensitive apps.",
		},
		{
			ID: "KT-004", Language: config.LangKotlin, Severity: config.SeverityMedium,
			Title:       "Insecure SharedPreferences for sensitive data",
			Description: "SharedPreferences stores data in plaintext accessible to rooted devices.",
			Pattern:     mustCompile(`(?i)getSharedPreferences|SharedPreferences`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-312", CVSS: 5.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/312.html"},
			Remediation: "Use EncryptedSharedPreferences from the Android Security library for sensitive data.",
		},
	}
}

func csharpRules() []Rule {
	return []Rule{
		{
			ID: "CS-001", Language: config.LangCSharp, Severity: config.SeverityHigh,
			Title:       "SQL Injection via string concatenation",
			Description: "Concatenating user input in SQL queries allows injection.",
			Pattern:     mustCompile(`(?i)(SqlCommand|ExecuteNonQuery|ExecuteReader)\s*\(.*\+`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-89", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
			Remediation: "Use parameterized queries: cmd.Parameters.AddWithValue(\"@id\", userId)",
		},
		{
			ID: "CS-002", Language: config.LangCSharp, Severity: config.SeverityHigh,
			Title:       "Hardcoded credential",
			Description: "Credentials hardcoded in C# source.",
			Pattern:     mustCompile(`(?i)(password|secret|apiKey)\s*=\s*"[^"]{4,}"`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-259", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/259.html"},
			Remediation: "Use Azure Key Vault, AWS Secrets Manager, or appsettings.json with Secret Manager tool.",
		},
		{
			ID: "CS-003", Language: config.LangCSharp, Severity: config.SeverityMedium,
			Title:       "Use of MD5 weak hash",
			Description: "MD5 is cryptographically broken.",
			Pattern:     mustCompile(`MD5\.Create\s*\(\s*\)|MD5CryptoServiceProvider`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-327", CVSS: 5.9,
			References:  []string{"https://cwe.mitre.org/data/definitions/327.html"},
			Remediation: "Use SHA256: SHA256.Create() or SHA512.Create()",
		},
		{
			ID: "CS-004", Language: config.LangCSharp, Severity: config.SeverityCritical,
			Title:       "Insecure deserialization (BinaryFormatter)",
			Description: "BinaryFormatter is insecure and can execute arbitrary code during deserialization.",
			Pattern:     mustCompile(`BinaryFormatter\s*\(`),
			OWASP:       config.OWASP_A08_SoftwareDataIntegrityFailures, CWE: "CWE-502", CVSS: 9.8,
			References:  []string{"https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide"},
			Remediation: "BinaryFormatter is deprecated. Use System.Text.Json, MessagePack, or Protobuf instead.",
		},
		{
			ID: "CS-005", Language: config.LangCSharp, Severity: config.SeverityHigh,
			Title:       "XSS via Response.Write without encoding",
			Description: "Writing user input directly to HTTP response enables XSS.",
			Pattern:     mustCompile(`(?i)Response\.Write\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-79", CVSS: 7.4,
			References:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
			Remediation: "Use HttpUtility.HtmlEncode() or WebUtility.HtmlEncode() before output.",
		},
	}
}

func shellRules() []Rule {
	return []Rule{
		{
			ID: "SH-001", Language: config.LangShell, Severity: config.SeverityHigh,
			Title:       "Command injection via eval",
			Description: "eval with user-controlled input enables arbitrary command execution.",
			Pattern:     mustCompile(`\beval\b.*\$`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-78", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
			Remediation: "Avoid eval. Use proper shell constructs. Quote all variables: \"$variable\"",
		},
		{
			ID: "SH-002", Language: config.LangShell, Severity: config.SeverityHigh,
			Title:       "Hardcoded credential in shell script",
			Description: "Credentials in shell scripts are easily discovered.",
			Pattern:     mustCompile(`(?i)(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*["']?[a-zA-Z0-9+/]{8,}`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-259", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/259.html"},
			Remediation: "Use environment variables or a secrets manager. Never hardcode credentials in scripts.",
		},
		{
			ID: "SH-003", Language: config.LangShell, Severity: config.SeverityMedium,
			Title:       "Unsafe temporary file creation",
			Description: "Creating predictable temp files enables symlink attacks (race condition).",
			Pattern:     mustCompile(`(?i)(mktemp|/tmp/[a-z])`),
			OWASP:       config.OWASP_A01_BrokenAccessControl, CWE: "CWE-377", CVSS: 5.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/377.html"},
			Remediation: "Use mktemp for temp file creation. Set restrictive umask. Use process substitution <() where possible.",
		},
		{
			ID: "SH-004", Language: config.LangShell, Severity: config.SeverityMedium,
			Title:       "curl/wget piped to bash (arbitrary code execution)",
			Description: "Downloading and directly executing scripts is a common attack vector.",
			Pattern:     mustCompile(`(?i)(curl|wget).*\|\s*(bash|sh|python|perl|ruby)`),
			OWASP:       config.OWASP_A08_SoftwareDataIntegrityFailures, CWE: "CWE-829", CVSS: 8.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/829.html"},
			Remediation: "Download scripts to a file, verify their checksum/signature before executing.",
		},
	}
}

func terraformRules() []Rule {
	return []Rule{
		{
			ID: "TF-001", Language: config.LangTerraform, Severity: config.SeverityHigh,
			Title:       "Hardcoded credential in Terraform",
			Description: "Credentials hardcoded in Terraform files are committed to version control.",
			Pattern:     mustCompile(`(?i)(password|secret|access_key|secret_key)\s*=\s*"[^"]{4,}"`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-259", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/259.html"},
			Remediation: "Use Terraform variables with sensitive=true and pass values via environment variables (TF_VAR_*) or HashiCorp Vault.",
		},
		{
			ID: "TF-002", Language: config.LangTerraform, Severity: config.SeverityHigh,
			Title:       "S3 bucket with public access",
			Description: "S3 buckets with public ACLs expose data to the internet.",
			Pattern:     mustCompile(`(?i)acl\s*=\s*"(public-read|public-read-write|authenticated-read)"`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-284", CVSS: 7.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/284.html"},
			Remediation: "Use private ACL and configure bucket policies explicitly. Enable S3 Block Public Access settings.",
		},
		{
			ID: "TF-003", Language: config.LangTerraform, Severity: config.SeverityMedium,
			Title:       "Security group allows unrestricted access (0.0.0.0/0)",
			Description: "Security groups open to all IPs expose services to the internet.",
			Pattern:     mustCompile(`cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0"`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-284", CVSS: 7.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/284.html"},
			Remediation: "Restrict CIDR blocks to known IP ranges. Use VPN or bastion hosts for administrative access.",
		},
		{
			ID: "TF-004", Language: config.LangTerraform, Severity: config.SeverityMedium,
			Title:       "S3 bucket encryption not enabled",
			Description: "S3 buckets without server-side encryption store data in plaintext.",
			Pattern:     mustCompile(`resource\s+"aws_s3_bucket"\s+"[^"]+"`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-311", CVSS: 5.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/311.html"},
			Remediation: "Enable SSE-S3 or SSE-KMS: add aws_s3_bucket_server_side_encryption_configuration resource.",
		},
		{
			ID: "TF-005", Language: config.LangTerraform, Severity: config.SeverityMedium,
			Title:       "RDS database without encryption",
			Description: "RDS instances without storage encryption expose data at rest.",
			Pattern:     mustCompile(`(?i)storage_encrypted\s*=\s*false`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-311", CVSS: 5.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/311.html"},
			Remediation: "Set storage_encrypted = true. Enable KMS encryption: kms_key_id = aws_kms_key.rds.arn",
		},
	}
}

func kubernetesRules() []Rule {
	return []Rule{
		{
			ID: "K8S-001", Language: config.LangKubernetes, Severity: config.SeverityHigh,
			Title:       "Container running as root",
			Description: "Containers running as root have elevated privileges and increase the blast radius of an escape.",
			Pattern:     mustCompile(`runAsUser:\s*0`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-250", CVSS: 7.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/250.html"},
			Remediation: "Set runAsNonRoot: true and runAsUser: 1000 (or higher) in securityContext.",
		},
		{
			ID: "K8S-002", Language: config.LangKubernetes, Severity: config.SeverityHigh,
			Title:       "Privileged container",
			Description: "Privileged containers have host-level access and can escape container isolation.",
			Pattern:     mustCompile(`privileged:\s*true`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-250", CVSS: 9.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/250.html"},
			Remediation: "Remove privileged: true. Use specific capabilities (add: [NET_BIND_SERVICE]) instead of full privileges.",
		},
		{
			ID: "K8S-003", Language: config.LangKubernetes, Severity: config.SeverityMedium,
			Title:       "Resource limits not set",
			Description: "Containers without CPU/memory limits can be used for resource exhaustion DoS.",
			Pattern:     mustCompile(`(?i)containers:\s*\n(?:(?!resources:)[\s\S]){1,500}image:`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-770", CVSS: 5.3,
			References:  []string{"https://cwe.mitre.org/data/definitions/770.html"},
			Remediation: "Always set resources.limits.cpu and resources.limits.memory for all containers.",
		},
		{
			ID: "K8S-004", Language: config.LangKubernetes, Severity: config.SeverityHigh,
			Title:       "Hardcoded secret in environment variable",
			Description: "Hardcoding secrets in YAML manifests exposes them in version control and the Kubernetes API.",
			Pattern:     mustCompile(`(?i)(value|password|secret|token):\s*["']?[a-zA-Z0-9+/]{8,}`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-259", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/259.html"},
			Remediation: "Use Kubernetes Secrets with valueFrom.secretKeyRef or external secret managers (Vault, AWS Secrets Manager with ESO).",
		},
	}
}

func htmlRules() []Rule {
	return []Rule{
		{
			ID: "HTML-001", Language: config.LangHTML, Severity: config.SeverityMedium,
			Title:       "Inline JavaScript event handler (XSS risk)",
			Description: "Inline event handlers can be exploited via XSS and bypass CSP.",
			Pattern:     mustCompile(`(?i)\son\w+\s*=\s*["']`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-79", CVSS: 6.1,
			References:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
			Remediation: "Move event handlers to external JavaScript files. Use Content Security Policy to block inline scripts.",
		},
		{
			ID: "HTML-002", Language: config.LangHTML, Severity: config.SeverityHigh,
			Title:       "Missing Content Security Policy (CSP)",
			Description: "Pages without CSP headers are more vulnerable to XSS attacks.",
			Pattern:     mustCompile(`(?i)<html`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-693", CVSS: 6.1,
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
			Remediation: "Add Content-Security-Policy meta tag or HTTP header: default-src 'self'; script-src 'self'",
		},
		{
			ID: "HTML-003", Language: config.LangHTML, Severity: config.SeverityLow,
			Title:       "Autocomplete enabled on sensitive input",
			Description: "Autocomplete on password fields can expose credentials in shared environments.",
			Pattern:     mustCompile(`(?i)<input[^>]+(type\s*=\s*["']password["'])[^>]*>`),
			OWASP:       config.OWASP_A07_AuthenticationFailures, CWE: "CWE-200", CVSS: 3.7,
			References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
			Remediation: "Add autocomplete=\"off\" to sensitive input fields: <input type=\"password\" autocomplete=\"off\">",
		},
	}
}

func genericRules() []Rule {
	return []Rule{
		{
			ID: "GEN-001", Language: config.LangGeneric, Severity: config.SeverityCritical,
			Title:       "Private key in source file",
			Description: "RSA, EC, or SSH private keys embedded in source code expose cryptographic material.",
			Pattern:     mustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-321", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/321.html"},
			Remediation: "Remove private keys from source code. Rotate all exposed keys immediately. Use a secrets manager.",
		},
		{
			ID: "GEN-002", Language: config.LangGeneric, Severity: config.SeverityCritical,
			Title:       "Certificate private key in source",
			Description: "PFX/P12 certificate private keys in source code expose authentication material.",
			Pattern:     mustCompile(`-----BEGIN CERTIFICATE-----`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-321", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/321.html"},
			Remediation: "Use certificate stores or secrets managers. Never commit certificates to VCS.",
		},
		{
			ID: "GEN-003", Language: config.LangGeneric, Severity: config.SeverityHigh,
			Title:       "TODO/FIXME security comment",
			Description: "Security-related TODO/FIXME comments indicate known unresolved vulnerabilities.",
			Pattern:     mustCompile(`(?i)(TODO|FIXME|HACK|XXX)\s*:?\s*(security|auth|sql|injection|xss|csrf|vuln|password|secret|token|fix|bypass|unsecure)`),
			OWASP:       config.OWASP_A06_InsecureDesign, CWE: "CWE-546", CVSS: 5.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/546.html"},
			Remediation: "Address all security-related TODOs before production deployment. Track issues in your issue tracker.",
		},
	}
}
