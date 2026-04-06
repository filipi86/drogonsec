# Usage Examples

## Basic Commands

\`\`\`bash
# Run
./bin/drogonsec

# Help
./bin/drogonsec --help

# Version
./bin/drogonsec --version
\`\`\`

---

## Threat Scanning with DRG-0x2

\`\`\`bash
./bin/drogonsec scan --module drg-0x2 --input <target>
\`\`\`

**Example output:**

\`\`\`json
{
  "threat_id": "TH-20260101-001",
  "severity": "high",
  "score": 0.87,
  "type": "malware_indicator",
  "description": "Suspicious pattern detected matching known threat signature",
  "timestamp": "2026-01-01T10:00:00Z"
}
\`\`\`

---

## Output to JSON

\`\`\`bash
./bin/drogonsec scan --module drg-0x2 --input ./target --output json > results.json
cat results.json | jq '.severity'
\`\`\`

---

## Batch Scanning

\`\`\`bash
for file in ./samples/*; do
  echo "Scanning: $file"
  ./bin/drogonsec scan --module drg-0x2 --input "$file"
done
\`\`\`

---

## Output Formats

| Format | Flag | Use Case |
|---|---|---|
| Text (default) | — | Human-readable terminal output |
| JSON | `--output json` | Integration with other tools |
| Verbose | `--verbose` | Debugging and detailed analysis |

---

## Keep Updated

\`\`\`bash
cd drogonsec
git pull origin main
make install
\`\`\`
