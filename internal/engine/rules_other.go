package engine

import "github.com/filipi86/drogonsec/internal/config"

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
			Title: "Unsafe use of math/rand for security",
			Description: "math/rand is not cryptographically secure and must not be used to generate " +
				"tokens, keys, salts, nonces, or other security-sensitive values.",
			// Only fire when a security-sensitive identifier appears on the same
			// line as the rand call. The previous pattern matched the bare
			// `math/rand` import and every rand.Int/Float/Perm call, flagging
			// load-balancing, jitter and cache-selection randomness (caddy even
			// aliases it `weakrand` on purpose) — almost entirely false positives.
			Pattern: mustCompile(`(?i)(password|passwd|secret|token|nonce|salt|apikey|api_key|session|csrf|otp|seed|privatekey|private_key).*rand\.(Int|Int31|Int63|Intn|Float32|Float64|Perm)\b|rand\.(Int|Int31|Int63|Intn|Float32|Float64|Perm)\b.*(password|passwd|secret|token|nonce|salt|apikey|api_key|session|csrf|otp|seed)`),
			OWASP:   config.OWASP_A04_CryptographicFailures, CWE: "CWE-338", CVSS: 5.9,
			References:  []string{"https://cwe.mitre.org/data/definitions/338.html"},
			Remediation: "Use crypto/rand for security-sensitive randomness.",
		},
		{
			// Low-confidence companion to GO-007: any math/rand call, reported at
			// LOW so a cross-line security use (rand here, token derived later) is
			// surfaced for review rather than dropped. Filter with --severity
			// MEDIUM to hide. Note: may also match crypto/rand.Int — review intent.
			ID: "GO-009", Language: config.LangGo, Severity: config.SeverityLow,
			Title:       "Possible weak randomness (review if security-sensitive)",
			Description: "A rand.* call that is only a problem if the value is used for tokens, keys, salts or nonces.",
			Pattern:     mustCompile(`\brand\.(Int|Int31|Int63|Intn|Float32|Float64|Perm)\s*\(`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-338", CVSS: 3.1,
			References:  []string{"https://cwe.mitre.org/data/definitions/338.html"},
			Remediation: "If the value is security-sensitive, use crypto/rand instead of math/rand.",
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
			// Suppress only unambiguous placeholders/examples and doctest lines.
			// We do NOT suppress weak literal values like 'admin'/'password' — a
			// hardcoded default credential is a real finding for the platform, not
			// noise (audit finding: suppressing $db_pass = 'admin' was an FN).
			AntiPattern: mustCompile(`(?i)>>>|=\s*["'][^"']*(fake|dummy|example|sample|placeholder|changeme|your[-_]|redacted|<[^>]+>|\{\{|test[-_]|foobar|\.\.\.|xxx)`),
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
			Title: "TLS/SSL verification disabled in OkHttp",
			Description: "Disabling certificate or hostname verification enables MITM attacks. " +
				"Flags trust-all managers and hostname verifiers that always return true.",
			// Only match idioms that actually DISABLE verification. The previous
			// pattern matched the bare API names hostnameVerifier/sslSocketFactory,
			// which are normal, secure configuration (custom sslSocketFactory is
			// how you pin certs) and even matched imports and class names like
			// CustomSSLSocketFactory — ~100% false positives on any TLS code.
			Pattern: mustCompile(`(?i)(trustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|HostnameVerifier\s*\{[^}]*->\s*true|fun\s+verify\b[^=\n]*=\s*true)`),
			OWASP:   config.OWASP_A04_CryptographicFailures, CWE: "CWE-295", CVSS: 7.4,
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
			// Match instantiation of the formatter, not the bare word: the old
			// pattern `BinaryFormatter\s*\(` also matched method declarations
			// named BinaryFormatter (e.g. `public byte[] BinaryFormatter()` in
			// benchmarks), which are not uses of the dangerous type.
			Pattern: mustCompile(`new\s+BinaryFormatter\s*\(`),
			OWASP:   config.OWASP_A08_SoftwareDataIntegrityFailures, CWE: "CWE-502", CVSS: 9.8,
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
		{
			ID: "TF-006", Language: config.LangTerraform, Severity: config.SeverityHigh,
			Title:       "Overly permissive IAM policy (wildcard action)",
			Description: "An IAM policy that grants Action \"*\" (often with Resource \"*\") violates least privilege and lets a compromised principal do anything.",
			Pattern:     mustCompile(`(?i)"Action"\s*:\s*"\*"|\bactions\s*=\s*\[\s*"\*"\s*\]`),
			OWASP:       config.OWASP_A01_BrokenAccessControl, CWE: "CWE-732", CVSS: 7.5,
			References:  []string{"https://cwe.mitre.org/data/definitions/732.html"},
			Remediation: "Scope IAM actions and resources to the minimum required; never grant Action \"*\" on Resource \"*\".",
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
		// K8S-003 (Resource limits not set) was removed: the original pattern used
		// a multi-line negative lookahead which RE2 does not support, and the
		// engine scans line-by-line, so this check cannot be implemented as a
		// regex. Proper detection requires a YAML parser and will be reintroduced
		// when that support lands.
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
		// HTML-002 re-implemented as a FILE-SCOPED check: fire once per HTML
		// document that has no Content-Security-Policy anywhere in the file
		// (meta tag or inline header). LOW confidence — a missing CSP is a
		// hardening gap, not a vuln, and fragments/snippets legitimately omit it.
		{
			ID: "HTML-002", Language: config.LangHTML, Severity: config.SeverityLow,
			Title:           "Missing Content Security Policy (CSP)",
			Description:     "This HTML document defines no Content-Security-Policy, so it relies entirely on other XSS defenses.",
			FileScoped:      true,
			Pattern:         mustCompile(`(?i)<html`),
			RequiredPattern: mustCompile(`(?i)Content-Security-Policy`),
			OWASP:           config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-693", CVSS: 3.1,
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
			Remediation: "Add a CSP via meta tag (<meta http-equiv=\"Content-Security-Policy\" ...>) or an HTTP response header.",
		},
		{
			ID: "HTML-003", Language: config.LangHTML, Severity: config.SeverityLow,
			Title:       "Autocomplete enabled on sensitive input",
			Description: "Autocomplete on password fields can expose credentials in shared environments.",
			Pattern:     mustCompile(`(?i)<input[^>]+(type\s*=\s*["']password["'])[^>]*>`),
			// Suppress finding when autocomplete attribute is already set to
			// off/new-password/current-password — those are the WCAG-recommended
			// safe values and already mitigate the issue (Issue #15).
			AntiPattern: mustCompile(`(?i)autocomplete\s*=\s*["'](off|new-password|current-password)["']`),
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
			// Suppress when the PEM marker is not committed key material but a
			// comment (`* -----BEGIN`), a Kotlin raw-string margin (`|-----BEGIN`),
			// or a string built at runtime (`append("-----BEGIN...\n")`) — the
			// pattern these PEM-generating test/cert utilities use.
			AntiPattern: mustCompile(`(?i)(^\s*[*#|]|//|\bappend\s*\()`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-321", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/321.html"},
			Remediation: "Remove private keys from source code. Rotate all exposed keys immediately. Use a secrets manager.",
		},
		// NOTE: the former GEN-002 rule matched `-----BEGIN CERTIFICATE-----` and
		// labelled it a "certificate private key". An X.509 CERTIFICATE block is
		// public material by definition (CA bundles, pinned certs, test certs);
		// it is not a secret. The rule was CRITICAL-severity and ~100% false
		// positive on any TLS code (41 hits on the OkHttp test tree). Private
		// keys — the real risk — are still covered by GEN-001 above.
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

func elixirRules() []Rule {
	return []Rule{
		{
			ID: "EX-001", Language: config.LangElixir, Severity: config.SeverityCritical,
			Title:       "Code injection via Code.eval_string/eval_quoted",
			Description: "Code.eval_string and Code.eval_quoted compile and run arbitrary Elixir at runtime; with untrusted input this is remote code execution.",
			Pattern:     mustCompile(`\bCode\.eval_(string|quoted)\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-94", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/94.html"},
			Remediation: "Never evaluate runtime-built code from untrusted input. Use explicit parsing/dispatch instead of Code.eval_*.",
		},
		{
			ID: "EX-002", Language: config.LangElixir, Severity: config.SeverityHigh,
			Title:       "Unsafe deserialization with binary_to_term",
			Description: "binary_to_term without the :safe option can construct arbitrary terms (atoms, funcs) from attacker data, enabling atom exhaustion and unsafe decoding.",
			Pattern:     mustCompile(`\b(?::erlang\.)?binary_to_term\s*\(`),
			// Suppress when the :safe option is passed on the same line.
			AntiPattern: mustCompile(`:safe`),
			OWASP:       config.OWASP_A08_SoftwareDataIntegrityFailures, CWE: "CWE-502", CVSS: 8.1,
			References:  []string{"https://cwe.mitre.org/data/definitions/502.html"},
			Remediation: "Pass the :safe option: :erlang.binary_to_term(bin, [:safe]); never deserialize untrusted terms.",
		},
		{
			ID: "EX-003", Language: config.LangElixir, Severity: config.SeverityHigh,
			Title:       "Command execution via shell (os.cmd/System.shell)",
			Description: ":os.cmd and System.shell run their argument through a shell; with interpolated input this enables OS command injection.",
			Pattern:     mustCompile(`(?::os\.cmd|\bSystem\.shell)\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-78", CVSS: 8.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
			Remediation: "Use System.cmd/3 with an explicit argument list (no shell), and validate inputs against an allowlist.",
		},
		{
			ID: "EX-004", Language: config.LangElixir, Severity: config.SeverityLow,
			Title:       "Atom exhaustion via String.to_atom",
			Description: "String.to_atom on untrusted input can exhaust the global atom table (atoms are never garbage-collected), crashing the VM.",
			Pattern:     mustCompile(`\bString\.to_atom\s*\(`),
			OWASP:       config.OWASP_A06_InsecureDesign, CWE: "CWE-400", CVSS: 5.9,
			References:  []string{"https://cwe.mitre.org/data/definitions/400.html"},
			Remediation: "Use String.to_existing_atom/1 so only already-defined atoms are accepted.",
		},
	}
}

func cRules() []Rule {
	return []Rule{
		{
			ID: "C-001", Language: config.LangC, Severity: config.SeverityHigh,
			Title:       "Use of gets() — unbounded read",
			Description: "gets() cannot bound its input and always risks a buffer overflow; it was removed from C11.",
			Pattern:     mustCompile(`\bgets\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-242", CVSS: 9.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/242.html"},
			Remediation: "Use fgets() with an explicit buffer size.",
		},
		{
			ID: "C-002", Language: config.LangC, Severity: config.SeverityMedium,
			Title:       "Unbounded string copy (strcpy/strcat/sprintf)",
			Description: "strcpy, strcat and sprintf write without a length bound and overflow the destination buffer when the source exceeds it.",
			Pattern:     mustCompile(`\b(strcpy|strcat|sprintf|vsprintf)\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-120", CVSS: 8.1,
			References:  []string{"https://cwe.mitre.org/data/definitions/120.html"},
			Remediation: "Use the bounded variants: strncpy/strlcpy, strncat/strlcat, snprintf.",
		},
		{
			ID: "C-003", Language: config.LangC, Severity: config.SeverityHigh,
			Title:       "Command execution via system()/popen()",
			Description: "system() and popen() run their argument through a shell; building the command from untrusted input enables OS command injection.",
			Pattern:     mustCompile(`\b(system|popen)\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-78", CVSS: 8.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
			Remediation: "Avoid the shell: use execve()/posix_spawn() with an argument vector, and validate inputs.",
		},
	}
}

// placeholderAnti is the shared "obvious placeholder / example value" suppressor
// reused by the hardcoded-secret rules across languages.
var placeholderAnti = `(?i)[:=]\s*["'][^"']*(fake|dummy|example|sample|placeholder|changeme|your[-_]|redacted|test[-_]|foobar|\.\.\.|xxx|<[^>]+>|\{\{)`

func swiftRules() []Rule {
	return []Rule{
		{
			ID: "SW-001", Language: config.LangSwift, Severity: config.SeverityHigh,
			Title:       "Hardcoded secret in Swift source",
			Description: "Secrets compiled into an app binary are recoverable by anyone who can inspect the IPA.",
			Pattern:     mustCompile(`(?i)(apikey|api_key|secret|password|passwd|token)\s*=\s*"[^"]{8,}"`),
			AntiPattern: mustCompile(placeholderAnti),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-798", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
			Remediation: "Store secrets in the Keychain or fetch them at runtime; never hardcode them in the app binary.",
		},
		{
			ID: "SW-002", Language: config.LangSwift, Severity: config.SeverityMedium,
			Title:       "Weak hash (MD5/SHA1) in Swift",
			Description: "MD5 and SHA-1 are broken for security use; CryptoKit's Insecure namespace and CC_MD5/CC_SHA1 expose them.",
			Pattern:     mustCompile(`\bInsecure\.(MD5|SHA1)\b|\bCC_(MD5|SHA1)\b`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-327", CVSS: 5.9,
			References:  []string{"https://cwe.mitre.org/data/definitions/327.html"},
			Remediation: "Use SHA-256 or stronger (CryptoKit SHA256); for passwords use a KDF (PBKDF2/Argon2).",
		},
		{
			ID: "SW-003", Language: config.LangSwift, Severity: config.SeverityHigh,
			Title:       "App Transport Security disabled (arbitrary loads)",
			Description: "NSAllowsArbitraryLoads disables ATS, allowing plaintext HTTP and weakening TLS for the whole app.",
			Pattern:     mustCompile(`NSAllowsArbitraryLoads`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-319", CVSS: 7.4,
			References:  []string{"https://cwe.mitre.org/data/definitions/319.html"},
			Remediation: "Remove NSAllowsArbitraryLoads; scope exceptions per-domain with NSExceptionDomains and require TLS.",
		},
	}
}

func dartRules() []Rule {
	return []Rule{
		{
			ID: "DART-001", Language: config.LangDart, Severity: config.SeverityHigh,
			Title:       "TLS certificate validation bypass",
			Description: "Overriding badCertificateCallback to accept any certificate disables TLS validation and enables MITM.",
			Pattern:     mustCompile(`badCertificateCallback`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-295", CVSS: 7.4,
			References:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
			Remediation: "Never return true unconditionally from badCertificateCallback; validate or pin the certificate.",
		},
		{
			ID: "DART-002", Language: config.LangDart, Severity: config.SeverityHigh,
			Title:       "Hardcoded secret in Dart source",
			Description: "Secrets compiled into a Flutter/Dart app are recoverable from the shipped bundle.",
			Pattern:     mustCompile(`(?i)(apikey|api_key|secret|password|passwd|token)\s*=\s*["'][^"']{8,}["']`),
			AntiPattern: mustCompile(placeholderAnti),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-798", CVSS: 8.0,
			References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
			Remediation: "Fetch secrets at runtime from a secure backend; do not embed them in the app.",
		},
		{
			ID: "DART-003", Language: config.LangDart, Severity: config.SeverityLow,
			Title:       "Possible weak randomness (dart:math Random)",
			Description: "dart:math Random() is not cryptographically secure. Low confidence: only a problem if used for tokens/keys.",
			Pattern:     mustCompile(`\bRandom\s*\(\s*\)`),
			AntiPattern: mustCompile(`Random\.secure`),
			OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-330", CVSS: 3.1,
			References:  []string{"https://cwe.mitre.org/data/definitions/330.html"},
			Remediation: "For security-sensitive values use Random.secure().",
		},
	}
}

func erlangRules() []Rule {
	return []Rule{
		{
			ID: "ERL-001", Language: config.LangErlang, Severity: config.SeverityHigh,
			Title:       "Unsafe deserialization with binary_to_term",
			Description: "binary_to_term without the safe option can build arbitrary terms from attacker data.",
			Pattern:     mustCompile(`\bbinary_to_term\s*\(`),
			AntiPattern: mustCompile(`safe`),
			OWASP:       config.OWASP_A08_SoftwareDataIntegrityFailures, CWE: "CWE-502", CVSS: 8.1,
			References:  []string{"https://cwe.mitre.org/data/definitions/502.html"},
			Remediation: "Use binary_to_term(Bin, [safe]); never deserialize untrusted terms.",
		},
		{
			ID: "ERL-002", Language: config.LangErlang, Severity: config.SeverityHigh,
			Title:       "Command execution via os:cmd",
			Description: "os:cmd/1 runs its argument through a shell; building it from untrusted input enables command injection.",
			Pattern:     mustCompile(`\bos:cmd\s*\(`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-78", CVSS: 8.8,
			References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
			Remediation: "Use erlang:open_port({spawn_executable, ...}) with an explicit arg list, and validate inputs.",
		},
		{
			ID: "ERL-003", Language: config.LangErlang, Severity: config.SeverityLow,
			Title:       "Atom exhaustion via list_to_atom/binary_to_atom",
			Description: "Creating atoms from untrusted input can exhaust the atom table and crash the VM.",
			Pattern:     mustCompile(`\b(list_to_atom|binary_to_atom)\s*\(`),
			OWASP:       config.OWASP_A06_InsecureDesign, CWE: "CWE-400", CVSS: 5.3,
			References:  []string{"https://cwe.mitre.org/data/definitions/400.html"},
			Remediation: "Use list_to_existing_atom/binary_to_existing_atom so only known atoms are created.",
		},
	}
}

func nginxRules() []Rule {
	return []Rule{
		{
			ID: "NGINX-001", Language: config.LangNginx, Severity: config.SeverityHigh,
			Title:       "Weak TLS protocol enabled",
			Description: "Enabling SSLv2/SSLv3/TLSv1/TLSv1.1 exposes connections to known protocol attacks (POODLE, BEAST).",
			// Match weak protocols explicitly. A bare TLSv1 (= TLS 1.0) is only
			// weak when it is NOT the prefix of TLSv1.2/1.3, so it must be
			// followed by whitespace/semicolon/EOL (RE2 has no negative lookahead).
			Pattern: mustCompile(`(?i)ssl_protocols\b[^;]*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1(\s|;|$))`),
			OWASP:   config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-327", CVSS: 7.4,
			References:  []string{"https://cwe.mitre.org/data/definitions/327.html"},
			Remediation: "Use only modern protocols: ssl_protocols TLSv1.2 TLSv1.3;",
		},
		{
			ID: "NGINX-002", Language: config.LangNginx, Severity: config.SeverityLow,
			Title:       "server_tokens on (version disclosure)",
			Description: "server_tokens on leaks the Nginx version in responses and error pages, aiding attackers.",
			Pattern:     mustCompile(`(?i)^\s*server_tokens\s+on\b`),
			OWASP:       config.OWASP_A05_Injection, CWE: "CWE-200", CVSS: 3.7,
			References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
			Remediation: "Set server_tokens off;",
		},
		{
			ID: "NGINX-003", Language: config.LangNginx, Severity: config.SeverityMedium,
			Title:       "Directory listing enabled (autoindex on)",
			Description: "autoindex on exposes a browsable directory listing, leaking file names and structure.",
			Pattern:     mustCompile(`(?i)^\s*autoindex\s+on\b`),
			OWASP:       config.OWASP_A02_SecurityMisconfiguration, CWE: "CWE-548", CVSS: 5.3,
			References:  []string{"https://cwe.mitre.org/data/definitions/548.html"},
			Remediation: "Set autoindex off; (the default) unless a public listing is intended.",
		},
	}
}
