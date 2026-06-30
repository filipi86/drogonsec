package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/filipi86/drogonsec/internal/engine"
)

func TestEngine_PythonSQLInjection(t *testing.T) {
	e := engine.New()

	// Create temp file with vulnerable code
	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "app.py")
	content := `
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	if len(findings) == 0 {
		t.Error("Expected SQL injection finding, got none")
		return
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY-001" {
			found = true
			if f.CWE != "CWE-89" {
				t.Errorf("Expected CWE-89, got %s", f.CWE)
			}
			break
		}
	}

	if !found {
		t.Errorf("Expected PY-001 (SQL Injection) rule, got rules: %v", getRuleIDs(findings))
	}
}

func TestEngine_PythonPickleDeser(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "deserialize.py")
	content := `
import pickle
import base64

def load_session(data):
    # VULNERABLE: arbitrary code execution via pickle
    session = pickle.loads(base64.b64decode(data))
    return session
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "PY-007" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected PY-007 (Pickle deserialization) finding")
	}
}

func TestEngine_JavaHardcodedPassword(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "Config.java")
	content := `
public class Config {
    private static final String DATABASE_PASSWORD = "super_secret_password123";
    private static final String API_KEY = "my-production-api-key";
    
    public String getPassword() {
        return DATABASE_PASSWORD;
    }
}
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "JAVA-003" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected JAVA-003 (Hardcoded password) finding, got: %v", getRuleIDs(findings))
	}
}

func TestEngine_JSEval(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "app.js")
	content := `
function processInput(userInput) {
    // VULNERABLE: code injection
    const result = eval(userInput);
    return result;
}
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "JS-001" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected JS-001 (eval) finding, got: %v", getRuleIDs(findings))
	}
}

func TestEngine_GoTLSVerifyDisabled(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "client.go")
	content := `
package main

import (
    "crypto/tls"
    "net/http"
)

func createInsecureClient() *http.Client {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // VULNERABLE
        },
    }
    return &http.Client{Transport: tr}
}
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "GO-005" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected GO-005 (InsecureSkipVerify) finding, got: %v", getRuleIDs(findings))
	}
}

// TestEngine_HTML003_AutocompleteFalsePositive guards Issue #15: password
// inputs that already carry autocomplete=off/new-password/current-password
// should not trigger HTML-003.
func TestEngine_HTML003_AutocompleteFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		html    string
		wantHit bool
	}{
		{"missing autocomplete triggers", `<input type="password" name="pass">`, true},
		{"autocomplete=off suppresses", `<input type="password" name="pass" autocomplete="off">`, false},
		{"autocomplete=new-password suppresses", `<input type="password" autocomplete="new-password">`, false},
		{"autocomplete=current-password suppresses", `<input type="password" autocomplete="current-password">`, false},
		{"autocomplete=on still triggers", `<input type="password" autocomplete="on">`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".html")
			if err := os.WriteFile(f, []byte(tc.html), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "HTML-003" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("HTML-003 on %q: got hit=%v, want %v (findings=%v)", tc.html, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_PY019_YamlLoaderFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"no loader triggers", `data = yaml.load(stream)`, true},
		{"explicit yaml.Loader triggers", `data = yaml.load(stream, Loader=yaml.Loader)`, true},
		{"UnsafeLoader triggers despite safe substring", `data = yaml.load(stream, Loader=yaml.UnsafeLoader)`, true},
		{"yaml.FullLoader suppresses", `data = yaml.load(stream, Loader=yaml.FullLoader)`, false},
		{"yaml.SafeLoader suppresses", `data = yaml.load(stream, Loader=yaml.SafeLoader)`, false},
		{"bare SafeLoader suppresses", `data = yaml.load(stream, Loader=SafeLoader)`, false},
		{"yaml.BaseLoader suppresses", `data = yaml.load(stream, Loader=yaml.BaseLoader)`, false},
		{"yaml.CSafeLoader suppresses", `data = yaml.load(stream, Loader=yaml.CSafeLoader)`, false},
		{"safe_load is not yaml.load", `data = yaml.safe_load(stream)`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".py")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "PY-019" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("PY-019 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_PY010_SSRFFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"request.args triggers", `r = requests.get(request.args.get("u"))`, true},
		{"flask.request triggers", `r = requests.get(flask.request.values["u"])`, true},
		{"self.request triggers", `r = requests.get(self.request.GET["u"])`, true},
		{"user_input triggers", `r = requests.post(user_input)`, true},
		{"bare url var does not trigger", `r = requests.get(url, headers=h)`, false},
		{"target var does not trigger", `r = requests.get(target, params=p)`, false},
		{"constant url does not trigger", `r = requests.get("https://api.example.com/v1")`, false},
		{"config-built url does not trigger", `r = requests.get(base_url + "/path")`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".py")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "PY-010" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("PY-010 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_PY003_HardcodedSecretFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"real-looking secret triggers", `API_KEY = "AKIA1B2C3D4REALKEY9Z"`, true},
		{"real password triggers", `password = "Sup3rS3cr3tValue!"`, true},
		{"fake placeholder suppressed", `SLACK_TOKEN = "fake-slack-token"`, false},
		{"your_ placeholder suppressed", `SEMGREP_APP_TOKEN = "your_semgrep_app_token"`, false},
		{"fake-client-secret suppressed", `CLIENT_SECRET = "fake-client-secret"`, false},
		{"test_ value suppressed", `token = "test_token"`, false},
		{"example value suppressed", `api_key = "example-key-value"`, false},
		{"doctest line suppressed", `>>> config.neo4j_password = "password"`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".py")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "PY-003" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("PY-003 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_PY011_SensitiveLoggingFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"fstring interpolating secret triggers", `logger.info(f"user password is {password}")`, true},
		{"percent-format secret triggers", `logger.debug("token=%s" % token)`, true},
		{"secret passed as arg triggers", `logger.error("auth failed", password)`, true},
		{"bare secret var triggers", `logger.debug(api_key)`, true},
		// FN recovery (audit): logging a secret via '+' concatenation.
		{"concat password triggers", `logger.info("user password: " + password)`, true},
		{"concat secret_value triggers", `logger.warning("session secret is " + secret_value)`, true},
		{"word in message only suppressed", `logger.warning("A Jamf password could not be found.")`, false},
		{"token in message, expiry logged suppressed", `logger.debug("Access token renewed in %s s", token_expiry)`, false},
		{"secrets in message only suppressed", `logger.debug("Running Secrets cleanup job.")`, false},
		{"token literal in fstring text suppressed", `logger.warning(f"{error_msg} for {bucket} - InvalidToken")`, false},
		{"tenant_id logged suppressed", `logger.info("Syncing tenant: %s", credentials.tenant_id)`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".py")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "PY-011" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("PY-011 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_KT003_OkHttpTLSFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"trustAllCerts triggers", `val tm = trustAllCerts`, true},
		{"ALLOW_ALL_HOSTNAME_VERIFIER triggers", `client.hostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)`, true},
		{"NoopHostnameVerifier triggers", `setHostnameVerifier(NoopHostnameVerifier())`, true},
		{"hostname verifier returning true triggers", `client.hostnameVerifier { _, _ -> true }`, true},
		{"custom sslSocketFactory does not trigger", `builder.sslSocketFactory(factory, trustManager)`, false},
		{"SSLSocketFactory import does not trigger", `import javax.net.ssl.SSLSocketFactory`, false},
		{"custom class name does not trigger", `class CustomSSLSocketFactory(delegate: SSLSocketFactory)`, false},
		{"plain hostnameVerifier reference does not trigger", `val v = client.hostnameVerifier`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".kt")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "KT-003" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("KT-003 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_GEN001_PrivateKeyFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"real embedded key triggers", `-----BEGIN PRIVATE KEY-----`, true},
		{"key assigned to var triggers", `val key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE"`, true},
		{"comment marker suppressed", ` * -----BEGIN PRIVATE KEY-----`, false},
		{"kotlin raw-string margin suppressed", `|-----BEGIN RSA PRIVATE KEY-----`, false},
		{"string builder suppressed", `append("-----BEGIN PRIVATE KEY-----\n")`, false},
		{"slash comment suppressed", `// -----BEGIN PRIVATE KEY-----`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".kt")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "GEN-001" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("GEN-001 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_GEN002_Removed(t *testing.T) {
	// A public X.509 certificate is not a secret; the GEN-002 rule that flagged
	// `-----BEGIN CERTIFICATE-----` was removed. Ensure it stays gone.
	e := engine.New()
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(f, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, fd := range e.Analyze(f) {
		if fd.RuleID == "GEN-002" {
			t.Errorf("GEN-002 should be removed but fired on a public certificate")
		}
	}
}

func TestEngine_PHP006_HardcodedPasswordFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"real password triggers", `$password = 'Pr0dP@ssw0rd!23';`, true},
		// FN recovery (audit): weak literal credentials are real findings, not
		// placeholders — they must fire.
		{"weak default admin triggers", `$db_pass = 'admin';`, true},
		{"literal password value triggers", `private $password = 'password';`, true},
		{"fake value suppressed", `$password = 'fake-secret-value';`, false},
		{"example value suppressed", `$passwd = 'example-pass';`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".php")
			if err := os.WriteFile(f, []byte("<?php\n"+tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "PHP-006" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("PHP-006 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_CS004_BinaryFormatterFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"instantiation triggers", `var f = new BinaryFormatter();`, true},
		{"typed instantiation triggers", `BinaryFormatter formatter = new BinaryFormatter();`, true},
		{"method declaration does not trigger", `public byte[] BinaryFormatter()`, false},
		{"method named return type does not trigger", `public TestClass BinaryFormatter()`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".cs")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "CS-004" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("CS-004 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_GO007_WeakRandFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"token from rand triggers", `token := rand.Intn(1000000)`, true},
		{"session id from rand triggers", `sessionID = fmt.Sprint(rand.Int63())`, true},
		{"cache selection does not trigger", `rnd := weakrand.IntN(len(c.cache))`, false},
		{"import does not trigger", `weakrand "math/rand/v2"`, false},
		{"jitter does not trigger", `delay := rand.Intn(maxJitterMillis)`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".go")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "GO-007" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("GO-007 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_PY014_WeakRandFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"token from random triggers", `token = ''.join(random.choice(alphabet) for _ in range(32))`, true},
		{"password from random triggers", `password = random.randint(1000, 9999)`, true},
		{"simulation choice does not trigger", `cas_item = random.choice(added_items)`, false},
		{"probability does not trigger", `use_cas = random.random() < cas_probability`, false},
		{"category sampling does not trigger", `category = random.choice(self.categories)`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".py")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "PY-014" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("PY-014 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_JS004_HardcodedSecretFalsePositive(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"real api key triggers", `const apiKey = "AKIAIOSFODNN7REALKEY";`, true},
		{"real secret triggers", `const secret = "9f8e7d6c5b4a3f2e1d0c9b8a";`, true},
		// FN recovery (audit): a real secret whose value contains the word
		// "secret" must NOT be suppressed.
		{"secret-containing value triggers", `const dbSecret = "secretLiveDbValue9f8e";`, true},
		{"fake value suppressed", `const apiKey = "fake-api-key-value";`, false},
		{"example value suppressed", `const token = "example-token-here";`, false},
		{"changeme value suppressed", `const secret = "changeme";`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".js")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "JS-004" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("JS-004 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_FileScopedMissingControls(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		file    string
		content string
		rule    string
		wantHit bool
	}{
		// CSP (HTML-002): fire when no CSP in the doc, suppress when present.
		{"html without csp", "a.html", "<!doctype html>\n<html><body>hi</body></html>", "HTML-002", true},
		{"html with csp meta", "b.html", "<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"></head></html>", "HTML-002", false},
		// Helmet (JS-011): fire when express app and no helmet, suppress with helmet.
		{"express without helmet", "c.js", "const app = express();\napp.listen(3000);", "JS-011", true},
		{"express with helmet", "d.js", "const helmet = require('helmet');\nconst app = express();\napp.use(helmet());", "JS-011", false},
		// CSRF (JS-016): fire when state-changing route and no csrf, suppress with csrf.
		{"routes without csrf", "e.js", "app.post('/x', h);\napp.delete('/y', h);", "JS-016", true},
		{"routes with csurf", "f.js", "app.use(csurf());\napp.post('/x', h);", "JS-016", false},
		// FileScoped should report once even with many matches.
		{"single finding per file", "g.html", "<html>\n<html>\n<html>", "HTML-002", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.file)
			if err := os.WriteFile(f, []byte(tc.content+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, fd := range e.Analyze(f) {
				if fd.RuleID == tc.rule {
					count++
				}
			}
			hit := count > 0
			if hit != tc.wantHit {
				t.Errorf("%s on %q: got hit=%v, want %v", tc.rule, tc.name, hit, tc.wantHit)
			}
			if tc.name == "single finding per file" && count != 1 {
				t.Errorf("FileScoped rule should report once per file, got %d", count)
			}
		})
	}
}

func TestEngine_ElixirRules(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		rule    string
		code    string
		wantHit bool
	}{
		{"EX-001", `Code.eval_string(user_input)`, true},
		{"EX-002", `:erlang.binary_to_term(payload)`, true},
		{"EX-002", `:erlang.binary_to_term(payload, [:safe])`, false}, // :safe suppresses
		{"EX-003", `:os.cmd(~c"ping #{host}")`, true},
		{"EX-003", `System.shell("ls " <> dir)`, true},
		{"EX-004", `String.to_atom(user_supplied)`, true},
		{"EX-004", `String.to_existing_atom(user_supplied)`, false}, // safe variant
	}

	for i, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.rule+"_"+string(rune('a'+i))+".ex")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == tc.rule {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("%s on %q: got hit=%v, want %v (findings=%v)", tc.rule, tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_CRules(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		rule    string
		code    string
		wantHit bool
	}{
		{"C-001", `gets(buf);`, true},
		{"C-002", `strcpy(dst, src);`, true},
		{"C-002", `sprintf(buf, "%s", name);`, true},
		{"C-002", `snprintf(buf, sizeof(buf), "%s", name);`, false}, // bounded, safe
		{"C-003", `system(cmd);`, true},
		{"C-003", `popen(cmd, "r");`, true},
	}

	for i, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.rule+"_"+string(rune('a'+i))+".c")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == tc.rule {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("%s on %q: got hit=%v, want %v (findings=%v)", tc.rule, tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_TF006_IAMWildcard(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "iam.tf")
	if err := os.WriteFile(f, []byte("resource \"aws_iam_policy\" \"p\" {\n  actions = [\"*\"]\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, fd := range e.Analyze(f) {
		if fd.RuleID == "TF-006" {
			hit = true
		}
	}
	if !hit {
		t.Errorf("TF-006 expected to fire on wildcard IAM action")
	}
}

func TestEngine_PY021_PossibleSSRF(t *testing.T) {
	// Low-confidence companion to PY-010: recovers the cross-line SSRF that the
	// high-confidence PY-010 rule intentionally misses, reported at LOW so it is
	// surfaced for review rather than silently dropped (audit FN recovery).
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		code    string
		wantHit bool
	}{
		{"request to url var", `return requests.get(url)`, true},
		{"request to target var", `return requests.get(target)`, true},
		{"request to endpoint var", `r = requests.post(endpoint, json=body)`, true},
		{"constant url not flagged", `requests.get("https://api.example.com/v1")`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tc.name+".py")
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			findings := e.Analyze(f)
			hit := false
			for _, fd := range findings {
				if fd.RuleID == "PY-021" {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("PY-021 on %q: got hit=%v, want %v (findings=%v)", tc.code, hit, tc.wantHit, getRuleIDs(findings))
			}
		})
	}
}

func TestEngine_NewLanguageRules(t *testing.T) {
	e := engine.New()
	tmpDir := t.TempDir()

	cases := []struct {
		rule    string
		ext     string
		code    string
		wantHit bool
	}{
		// Swift
		{"SW-001", "swift", `let apiKey = "AKIAIOSFODNN7REALKEY9"`, true},
		{"SW-001", "swift", `let apiKey = "example-key-value"`, false}, // placeholder
		{"SW-002", "swift", `let h = Insecure.MD5.hash(data: d)`, true},
		{"SW-003", "swift", `<key>NSAllowsArbitraryLoads</key><true/>`, true},
		// Dart
		{"DART-001", "dart", `client.badCertificateCallback = (cert, host, port) => true;`, true},
		{"DART-002", "dart", `const apiKey = "sk_live_realDartValue99";`, true},
		{"DART-003", "dart", `var r = Random();`, true},
		{"DART-003", "dart", `var r = Random.secure();`, false}, // secure variant
		// Erlang
		{"ERL-001", "erl", `T = binary_to_term(Bin).`, true},
		{"ERL-001", "erl", `T = binary_to_term(Bin, [safe]).`, false}, // safe
		{"ERL-002", "erl", `os:cmd("ping " ++ Host).`, true},
		{"ERL-003", "erl", `A = list_to_atom(Input).`, true},
		// Nginx
		{"NGINX-001", "conf", `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;`, true},
		{"NGINX-001", "conf", `ssl_protocols TLSv1.2 TLSv1.3;`, false}, // modern only
		{"NGINX-002", "conf", `server_tokens on;`, true},
		{"NGINX-003", "conf", `autoindex on;`, true},
	}

	for i, tc := range cases {
		t.Run(tc.rule+"_"+string(rune('a'+i)), func(t *testing.T) {
			f := filepath.Join(tmpDir, "f"+string(rune('a'+i))+"."+tc.ext)
			if err := os.WriteFile(f, []byte(tc.code+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			hit := false
			for _, fd := range e.Analyze(f) {
				if fd.RuleID == tc.rule {
					hit = true
					break
				}
			}
			if hit != tc.wantHit {
				t.Errorf("%s on %q: got hit=%v, want %v", tc.rule, tc.code, hit, tc.wantHit)
			}
		})
	}
}

func TestEngine_RuleCount(t *testing.T) {
	e := engine.New()
	count := e.RuleCount()
	if count < 50 {
		t.Errorf("Expected at least 50 rules, got %d", count)
	}
	t.Logf("Total rules loaded: %d", count)
}

// helper
func getRuleIDs(findings []engine.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}
