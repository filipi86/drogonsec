package config

// ScanConfig holds all configuration for a scan session
type ScanConfig struct {
	TargetPath   string
	OutputFormat string
	OutputFile   string
	IgnorePaths  []string
	EnableAI     bool
	ClaudeAPIKey string
	GitHistory   bool
	EnableSAST   bool
	EnableSCA    bool
	EnableLeaks  bool
	MinSeverity  string
	Languages    []string
	MaxWorkers   int
	Verbose      bool
	RulesDir     string // path to custom YAML rules directory
}

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// SeverityWeight returns numeric weight for comparison
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Language represents a supported programming language
type Language string

const (
	LangJava       Language = "Java"
	LangKotlin     Language = "Kotlin"
	LangJavaScript Language = "JavaScript"
	LangTypeScript Language = "TypeScript"
	LangPython     Language = "Python"
	LangRuby       Language = "Ruby"
	LangGo         Language = "Go"
	LangCSharp     Language = "C#"
	LangPHP        Language = "PHP"
	LangSwift      Language = "Swift"
	LangDart       Language = "Dart"
	LangElixir     Language = "Elixir"
	LangErlang     Language = "Erlang"
	LangShell      Language = "Shell"
	LangC          Language = "C"
	LangHTML       Language = "HTML"
	LangTerraform  Language = "Terraform"
	LangKubernetes Language = "Kubernetes"
	LangNginx      Language = "Nginx"
	LangLeaks      Language = "Leaks"
	LangGeneric    Language = "Generic"
	LangUnknown    Language = "Unknown"
)

// FindingType categorizes the type of security finding
type FindingType string

const (
	FindingTypeSAST  FindingType = "SAST"
	FindingTypeSCA   FindingType = "SCA"
	FindingTypeLeaks FindingType = "Leaks"
	FindingTypeIaC   FindingType = "IaC"
)

// OWASPCategory represents OWASP Top 10 2025 categories
type OWASPCategory string

const (
	OWASP_A01_BrokenAccessControl              OWASPCategory = "A01:2025 - Broken Access Control"
	OWASP_A02_SecurityMisconfiguration         OWASPCategory = "A02:2025 - Security Misconfiguration"
	OWASP_A03_SoftwareSupplyChainFailures      OWASPCategory = "A03:2025 - Software Supply Chain Failures"
	OWASP_A04_CryptographicFailures            OWASPCategory = "A04:2025 - Cryptographic Failures"
	OWASP_A05_Injection                        OWASPCategory = "A05:2025 - Injection"
	OWASP_A06_InsecureDesign                   OWASPCategory = "A06:2025 - Insecure Design"
	OWASP_A07_AuthenticationFailures           OWASPCategory = "A07:2025 - Authentication Failures"
	OWASP_A08_SoftwareDataIntegrityFailures    OWASPCategory = "A08:2025 - Software or Data Integrity Failures"
	OWASP_A09_SecurityLoggingAlertingFailures  OWASPCategory = "A09:2025 - Security Logging & Alerting Failures"
	OWASP_A10_MishandlingExceptionalConditions OWASPCategory = "A10:2025 - Mishandling of Exceptional Conditions"
)

// FileExtensionMap maps file extensions to languages
var FileExtensionMap = map[string]Language{
	".java":   LangJava,
	".kt":     LangKotlin,
	".kts":    LangKotlin,
	".js":     LangJavaScript,
	".jsx":    LangJavaScript,
	".mjs":    LangJavaScript,
	".ts":     LangTypeScript,
	".tsx":    LangTypeScript,
	".py":     LangPython,
	".pyw":    LangPython,
	".rb":     LangRuby,
	".go":     LangGo,
	".cs":     LangCSharp,
	".php":    LangPHP,
	".swift":  LangSwift,
	".dart":   LangDart,
	".ex":     LangElixir,
	".exs":    LangElixir,
	".erl":    LangErlang,
	".hrl":    LangErlang,
	".sh":     LangShell,
	".bash":   LangShell,
	".zsh":    LangShell,
	".fish":   LangShell,
	".c":      LangC,
	".cpp":    LangC,
	".cc":     LangC,
	".h":      LangC,
	".hpp":    LangC,
	".html":   LangHTML,
	".htm":    LangHTML,
	".tf":     LangTerraform,
	".tfvars": LangTerraform,
	".hcl":    LangTerraform,
}

// DefaultIgnorePaths are always ignored during scanning
var DefaultIgnorePaths = []string{
	".git",
	"node_modules",
	"vendor",
	".cache",
	"dist",
	"build",
	"target",
	"__pycache__",
	".pytest_cache",
	".tox",
	"venv",
	".venv",
	"env",
	".mypy_cache",
	".gradle",
	".m2",
}
