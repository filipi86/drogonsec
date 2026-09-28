package sca

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ============= maven =============

// PomXMLParser reads a Maven project's full dependency tree.
//
// Maven has no lockfile. What it resolves is decided by the project's pom.xml
// together with the POM of every artifact reached from it — each dependency's
// own dependencies, its parent POMs, the BOMs it imports — and Maven keeps
// every one of those POMs in the local repository (~/.m2/repository) as soon
// as it has resolved the project once, by a build, a test run or
// `mvn dependency:resolve`. A released POM never changes, so the local
// repository holds exactly the inputs the resolution was made from.
//
// The parser performs that resolution offline, by Maven's own rules, and was
// checked against `mvn dependency:tree` on the same projects:
//
//   - a POM inherits from its parents: properties, dependencies and managed
//     dependencies, with the child winning, before anything is interpolated;
//   - <dependencyManagement> imports of BOMs (scope import, type pom) add the
//     BOM's managed versions without overriding the ones the POM states;
//   - the tree is walked breadth-first and the nearest declaration of an
//     artifact wins, the first one at equal depth — so a direct dependency
//     always beats a transitive one;
//   - the root project's managed versions override those of every transitive
//     dependency, which is why a <dependencyManagement> entry is how a Maven
//     project patches a vulnerable library it never named;
//   - test, provided and optional dependencies of a dependency are not
//     transitive, exclusions apply to the whole subtree below them, and scopes
//     narrow as they propagate.
//
// Sibling modules of a multi-module build are read from the repository rather
// than the local repository, and are not reported: they are the project's own
// code. They still appear on the route of what they pull in.
//
// Where a POM is not in the local repository — the project has never been
// built on this machine — the artifact itself is still reported, at the
// version its declarer asked for, and only what lies below it is lost. The
// scan says how many POMs it could not find.
type PomXMLParser struct {
	models  map[string]*mavenModel
	missing map[string]bool
}

func (p *PomXMLParser) Name() string    { return "maven" }
func (p *PomXMLParser) Files() []string { return []string{"pom.xml"} }
func (p *PomXMLParser) Lockfile()       {}

// notes reports what the parser could not see, for the engine to print.
func (p *PomXMLParser) notes() []string {
	if len(p.missing) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d Maven POMs are not in the local repository, so what they pull in is not covered — run `mvn dependency:resolve` once to include it", len(p.missing))}
}

func (p *PomXMLParser) Parse(path string) ([]Dependency, error) {
	if p.models == nil {
		p.models = make(map[string]*mavenModel)
		p.missing = make(map[string]bool)
	}
	r := &mavenResolver{
		models:  p.models,
		missing: p.missing,
		locate:  mavenLocalRepoLocator(mavenLocalRepo()),
	}
	return r.resolveProject(path)
}

// ---- POM model ----

type pomFile struct {
	GroupID      string          `xml:"groupId"`
	ArtifactID   string          `xml:"artifactId"`
	Version      string          `xml:"version"`
	Parent       *pomParent      `xml:"parent"`
	Properties   pomProperties   `xml:"properties"`
	Management   []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
	Modules      []string        `xml:"modules>module"`
	Profiles     []pomProfile    `xml:"profiles>profile"`
	Relocation   *pomRelocation  `xml:"distributionManagement>relocation"`
}

type pomParent struct {
	GroupID      string  `xml:"groupId"`
	ArtifactID   string  `xml:"artifactId"`
	Version      string  `xml:"version"`
	RelativePath *string `xml:"relativePath"`
}

type pomProfile struct {
	ActiveByDefault string          `xml:"activation>activeByDefault"`
	Property        *pomActivation  `xml:"activation>property"`
	Properties      pomProperties   `xml:"properties"`
	Management      []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
	Dependencies    []pomDependency `xml:"dependencies>dependency"`
}

type pomActivation struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

type pomRelocation struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type pomDependency struct {
	GroupID    string         `xml:"groupId"`
	ArtifactID string         `xml:"artifactId"`
	Version    string         `xml:"version"`
	Type       string         `xml:"type"`
	Classifier string         `xml:"classifier"`
	Scope      string         `xml:"scope"`
	Optional   string         `xml:"optional"`
	Exclusions []pomExclusion `xml:"exclusions>exclusion"`
}

type pomExclusion struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

// pomProperties reads <properties>, whose children are named by the property
// rather than by a fixed schema.
type pomProperties map[string]string

func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	props := make(pomProperties)
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return err
			}
			props[t.Name.Local] = strings.TrimSpace(value)
		case xml.EndElement:
			*p = props
			return nil
		}
	}
}

// key is Maven's identity for an artifact in conflict resolution and in
// dependency management: coordinates without the version.
func (d pomDependency) key() string {
	typ := d.Type
	if typ == "" {
		typ = "jar"
	}
	return d.GroupID + ":" + d.ArtifactID + ":" + typ + ":" + d.Classifier
}

func (d pomDependency) name() string { return d.GroupID + ":" + d.ArtifactID }

// mavenModel is a POM after inheritance, interpolation and BOM imports: the
// effective model, as far as dependencies are concerned.
type mavenModel struct {
	groupID, artifactID, version string
	managed                      map[string]pomDependency
	dependencies                 []pomDependency
	relocation                   *pomRelocation
	file                         string
}

// ---- resolution ----

type pomLocator func(groupID, artifactID, version string) string

type mavenResolver struct {
	models  map[string]*mavenModel
	missing map[string]bool
	locate  pomLocator

	// reactor maps the coordinates of every module of the multi-module build
	// the scanned POM belongs to onto its pom.xml.
	reactor map[string]string
}

const maxPOMDepth = 32

func (r *mavenResolver) resolveProject(path string) ([]Dependency, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	r.reactor = r.indexReactor(abs)

	root, err := r.modelFromFile(abs, 0)
	if err != nil {
		return nil, err
	}
	return r.walk(root, path), nil
}

type mavenNode struct {
	dep        pomDependency
	model      *mavenModel
	scope      string
	exclusions []pomExclusion
	path       []string
	own        bool // a module of the reactor rather than a dependency
}

func (r *mavenResolver) walk(root *mavenModel, manifest string) []Dependency {
	winners := make(map[string]string) // conflict key → selected version
	var queue []*mavenNode
	var deps []Dependency
	index := make(map[string]int) // conflict key → position in deps

	enqueue := func(parent *mavenNode, d pomDependency) {
		if d.GroupID == "" || d.ArtifactID == "" || d.Scope == "system" || d.Scope == "import" {
			return
		}
		key := d.key()
		if _, seen := winners[key]; seen {
			return
		}
		version, ranged := r.selectVersion(d)
		winners[key] = version

		n := &mavenNode{dep: d, scope: d.Scope}
		if n.scope == "" {
			n.scope = "compile"
		}
		n.dep.Version = version
		if parent != nil {
			n.scope = narrowScope(parent.scope, d.Scope)
			n.exclusions = append(append([]pomExclusion{}, parent.exclusions...), d.Exclusions...)
			n.path = append(append([]string{}, parent.path...), parent.dep.name())
		} else {
			n.exclusions = append([]pomExclusion{}, d.Exclusions...)
		}

		if file, ok := r.reactor[d.GroupID+":"+d.ArtifactID+":"+version]; ok {
			n.own = true
			n.model, _ = r.modelFromFile(file, 0)
		} else if version != "" && !ranged {
			n.model = r.modelFromRepo(d.GroupID, d.ArtifactID, version, 0)
			if n.model != nil && n.model.relocation != nil {
				n = r.relocate(n)
			}
		}
		queue = append(queue, n)

		// A sibling module is the project's own code, and an artifact
		// whose version could not be determined has nothing to be matched
		// against. Both are still walked through, when a POM is at hand.
		if n.own || version == "" || len(queue) > maxInstalledPackages {
			return
		}
		index[key] = len(deps)
		dep := Dependency{
			Name:           n.dep.name(),
			Version:        n.dep.Version,
			VersionIsRange: ranged,
			Ecosystem:      "maven",
			File:           manifest,
			Direct:         parent == nil,
		}
		if !dep.Direct {
			dep.Path = n.path
		}
		deps = append(deps, dep)
	}

	for _, d := range root.dependencies {
		enqueue(nil, d)
	}

	for i := 0; i < len(queue); i++ {
		n := queue[i]
		if n.model == nil {
			continue
		}
		var requires []Ref
		for _, child := range n.model.dependencies {
			// A sibling module is depended on like any other artifact, so
			// the same rules apply to what it brings along.
			if child.Scope == "test" || child.Scope == "provided" || child.Optional == "true" {
				continue
			}
			if excluded(child, n.exclusions) {
				continue
			}
			// The root's dependency management overrides the version of
			// every transitive dependency, its scope where it states one, and
			// adds its exclusions.
			if managed, ok := root.managed[child.key()]; ok {
				if managed.Version != "" {
					child.Version = managed.Version
				}
				if managed.Scope != "" {
					child.Scope = managed.Scope
				}
				child.Exclusions = append(append([]pomExclusion{}, child.Exclusions...), managed.Exclusions...)
			}
			enqueue(n, child)
			if v, ok := winners[child.key()]; ok && !r.isOwn(child, v) {
				requires = append(requires, Ref{Name: child.name(), Version: v})
			}
		}
		if at, ok := index[n.dep.key()]; ok && !n.own {
			deps[at].Requires = requires
		}
	}

	return deps
}

func (r *mavenResolver) isOwn(d pomDependency, version string) bool {
	_, ok := r.reactor[d.GroupID+":"+d.ArtifactID+":"+version]
	return ok
}

// relocate follows a POM's <relocation>, which says the artifact has moved to
// new coordinates — mysql:mysql-connector-java became com.mysql:mysql-
// connector-j — and that Maven should resolve those instead.
func (r *mavenResolver) relocate(n *mavenNode) *mavenNode {
	for hops := 0; hops < 4 && n.model != nil && n.model.relocation != nil; hops++ {
		rel := n.model.relocation
		if rel.GroupID != "" {
			n.dep.GroupID = rel.GroupID
		}
		if rel.ArtifactID != "" {
			n.dep.ArtifactID = rel.ArtifactID
		}
		if rel.Version != "" {
			n.dep.Version = rel.Version
		}
		n.model = r.modelFromRepo(n.dep.GroupID, n.dep.ArtifactID, n.dep.Version, 0)
	}
	return n
}

// narrowScope is how a dependency's scope combines with the scope of whatever
// brought it in. A compile dependency of a test dependency is needed for the
// tests only; a runtime dependency of a compile one is needed at runtime only.
func narrowScope(parent, child string) string {
	if child == "" {
		child = "compile"
	}
	switch parent {
	case "test", "provided":
		return parent
	case "runtime":
		return "runtime"
	}
	return child
}

func excluded(d pomDependency, exclusions []pomExclusion) bool {
	for _, e := range exclusions {
		if (e.GroupID == "*" || e.GroupID == d.GroupID) && (e.ArtifactID == "*" || e.ArtifactID == d.ArtifactID) {
			return true
		}
	}
	return false
}

// selectVersion turns a declared version into the one Maven uses. A plain
// version is a "soft" requirement and is used as written; a range such as
// [1.2,2.0) is answered from the versions present in the local repository,
// which is what Maven itself consults when working offline.
func (r *mavenResolver) selectVersion(d pomDependency) (string, bool) {
	v := strings.TrimSpace(d.Version)
	if v == "" || (!strings.HasPrefix(v, "[") && !strings.HasPrefix(v, "(")) {
		return v, false
	}
	if picked := r.pickFromRange(d.GroupID, d.ArtifactID, v); picked != "" {
		return picked, false
	}
	return v, true
}

func (r *mavenResolver) pickFromRange(groupID, artifactID, spec string) string {
	probe := r.locate(groupID, artifactID, "0")
	if probe == "" {
		return ""
	}
	// probe is <repo>/<group>/<artifact>/0/<artifact>-0.pom; the versions
	// are the sibling directories of its version directory.
	entries, err := os.ReadDir(filepath.Dir(filepath.Dir(probe)))
	if err != nil {
		return ""
	}
	best := ""
	for _, e := range entries {
		if e.IsDir() && mavenRangeContains(spec, e.Name()) && (best == "" || compareVersions(e.Name(), best) > 0) {
			best = e.Name()
		}
	}
	return best
}

// mavenRangeContains reports whether version lies in a Maven version range:
// "[1.0]", "[1.0,2.0)", "(,1.5]", or a union of those, "[1.0,1.2),[1.3,)".
func mavenRangeContains(spec, version string) bool {
	for _, part := range splitMavenRanges(spec) {
		if len(part) < 3 {
			continue
		}
		lowInc, highInc := part[0] == '[', part[len(part)-1] == ']'
		inner := part[1 : len(part)-1]
		low, high, isSpan := strings.Cut(inner, ",")
		low, high = strings.TrimSpace(low), strings.TrimSpace(high)
		if !isSpan {
			if compareVersions(version, low) == 0 {
				return true
			}
			continue
		}
		if low != "" {
			c := compareVersions(version, low)
			if c < 0 || (c == 0 && !lowInc) {
				continue
			}
		}
		if high != "" {
			c := compareVersions(version, high)
			if c > 0 || (c == 0 && !highInc) {
				continue
			}
		}
		return true
	}
	return false
}

func splitMavenRanges(spec string) []string {
	var parts []string
	depth, start := 0, 0
	for i, c := range spec {
		switch c {
		case '[', '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ']', ')':
			depth--
			if depth == 0 {
				parts = append(parts, spec[start:i+1])
			}
		}
	}
	return parts
}

// ---- effective model ----

func (r *mavenResolver) modelFromRepo(groupID, artifactID, version string, depth int) *mavenModel {
	coords := groupID + ":" + artifactID + ":" + version
	if file, ok := r.reactor[coords]; ok {
		m, _ := r.modelFromFile(file, depth)
		return m
	}
	if m, ok := r.models[coords]; ok {
		return m
	}
	file := r.locate(groupID, artifactID, version)
	if file == "" {
		r.missing[coords] = true
		r.models[coords] = nil
		return nil
	}
	m, err := r.modelFromFile(file, depth)
	if err != nil {
		r.missing[coords] = true
		m = nil
	}
	r.models[coords] = m
	return m
}

func (r *mavenResolver) modelFromFile(file string, depth int) (*mavenModel, error) {
	if m, ok := r.models[file]; ok {
		if m == nil {
			return nil, fmt.Errorf("unreadable POM %s", file)
		}
		return m, nil
	}
	if depth > maxPOMDepth {
		return nil, fmt.Errorf("POM inheritance deeper than %d at %s", maxPOMDepth, file)
	}
	// Mark the file before recursing so a parent or import cycle ends here
	// rather than exhausting the stack.
	r.models[file] = nil

	chain, err := r.lineage(file, depth)
	if err != nil {
		return nil, err
	}
	m := r.effective(chain, depth)
	m.file = file
	r.models[file] = m
	return m, nil
}

// lineage reads a POM and its parents, eldest first.
func (r *mavenResolver) lineage(file string, depth int) ([]*pomFile, error) {
	var chain []*pomFile
	current := file
	for hops := 0; current != "" && hops < maxPOMDepth; hops++ {
		pom, err := readPOM(current)
		if err != nil {
			if len(chain) == 0 {
				return nil, err
			}
			break
		}
		applyActiveProfiles(pom)
		chain = append([]*pomFile{pom}, chain...)
		if pom.Parent == nil || pom.Parent.ArtifactID == "" {
			break
		}
		current = r.parentFile(current, pom.Parent)
		if current == "" {
			r.missing[pom.Parent.GroupID+":"+pom.Parent.ArtifactID+":"+pom.Parent.Version] = true
		}
	}
	return chain, nil
}

// parentFile finds a parent POM: at its relativePath — ../pom.xml unless
// stated — when the POM there carries the parent's coordinates, and in the
// local repository otherwise.
func (r *mavenResolver) parentFile(child string, parent *pomParent) string {
	rel := "../pom.xml"
	if parent.RelativePath != nil {
		rel = strings.TrimSpace(*parent.RelativePath)
	}
	if rel != "" {
		candidate := filepath.Join(filepath.Dir(child), filepath.FromSlash(rel))
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			candidate = filepath.Join(candidate, "pom.xml")
		}
		if pom, err := readPOM(candidate); err == nil && pom.ArtifactID == parent.ArtifactID {
			group, version := pom.GroupID, pom.Version
			if pom.Parent != nil {
				if group == "" {
					group = pom.Parent.GroupID
				}
				if version == "" {
					version = pom.Parent.Version
				}
			}
			if group == parent.GroupID && (version == parent.Version || strings.Contains(parent.Version, "${")) {
				return candidate
			}
		}
	}
	if file, ok := r.reactor[parent.GroupID+":"+parent.ArtifactID+":"+parent.Version]; ok {
		return file
	}
	return r.locate(parent.GroupID, parent.ArtifactID, parent.Version)
}

// effective merges a lineage into one model, in the order Maven assembles it:
// inheritance first, interpolation against the merged properties next, BOM
// imports last.
func (r *mavenResolver) effective(chain []*pomFile, depth int) *mavenModel {
	props := make(map[string]string)
	m := &mavenModel{managed: make(map[string]pomDependency)}

	var parentGroup, parentVersion string
	for _, pom := range chain {
		if pom.Parent != nil {
			parentGroup, parentVersion = pom.Parent.GroupID, pom.Parent.Version
		}
		if pom.GroupID != "" {
			m.groupID = pom.GroupID
		} else if pom.Parent != nil {
			m.groupID = pom.Parent.GroupID
		}
		if pom.Version != "" {
			m.version = pom.Version
		} else if pom.Parent != nil {
			m.version = pom.Parent.Version
		}
		m.artifactID = pom.ArtifactID
		for k, v := range pom.Properties {
			props[k] = v
		}
	}
	self := chain[len(chain)-1]
	m.relocation = self.Relocation

	for _, alias := range []string{"project.", "pom.", ""} {
		for field, value := range map[string]string{"groupId": m.groupID, "artifactId": m.artifactID, "version": m.version} {
			// project.* always names the model. The bare, deprecated form
			// gives way to a property of the same name.
			if _, defined := props[alias+field]; alias == "" && defined {
				continue
			}
			props[alias+field] = value
		}
	}
	props["project.parent.groupId"], props["parent.groupId"] = parentGroup, parentGroup
	props["project.parent.version"], props["parent.version"] = parentVersion, parentVersion
	interpolate := func(s string) string { return interpolateMaven(s, props) }
	expand := func(d pomDependency) pomDependency {
		d.GroupID, d.ArtifactID = interpolate(d.GroupID), interpolate(d.ArtifactID)
		d.Version, d.Type = interpolate(d.Version), interpolate(d.Type)
		d.Classifier, d.Scope = interpolate(d.Classifier), interpolate(d.Scope)
		d.Optional = interpolate(d.Optional)
		for i, e := range d.Exclusions {
			d.Exclusions[i] = pomExclusion{GroupID: interpolate(e.GroupID), ArtifactID: interpolate(e.ArtifactID)}
		}
		return d
	}
	if m.relocation != nil {
		rel := *m.relocation
		rel.GroupID, rel.ArtifactID, rel.Version = interpolate(rel.GroupID), interpolate(rel.ArtifactID), interpolate(rel.Version)
		m.relocation = &rel
	}

	// Managed entries and dependencies, the child winning over its parents.
	var imports []pomDependency
	importSeen := make(map[string]bool)
	var order []string
	deps := make(map[string]pomDependency)
	for _, pom := range chain {
		for _, d := range pom.Management {
			d = expand(d)
			if d.Scope == "import" {
				// A child re-declaring the import replaces the parent's.
				if !importSeen[d.key()] {
					importSeen[d.key()] = true
					imports = append(imports, d)
				}
				continue
			}
			m.managed[d.key()] = d
		}
		for _, d := range pom.Dependencies {
			d = expand(d)
			if _, ok := deps[d.key()]; !ok {
				order = append(order, d.key())
			}
			deps[d.key()] = d
		}
	}

	// A BOM adds what the POM does not already manage, and an earlier import
	// wins over a later one.
	for _, imp := range imports {
		bom := r.modelFromRepo(imp.GroupID, imp.ArtifactID, imp.Version, depth+1)
		if bom == nil {
			continue
		}
		for _, key := range sortedKeys(bom.managed) {
			if _, ok := m.managed[key]; !ok {
				m.managed[key] = bom.managed[key]
			}
		}
	}

	for _, key := range order {
		d := deps[key]
		if managed, ok := m.managed[key]; ok {
			if d.Version == "" {
				d.Version = managed.Version
			}
			if d.Scope == "" {
				d.Scope = managed.Scope
			}
			if len(d.Exclusions) == 0 {
				d.Exclusions = managed.Exclusions
			}
			if d.Optional == "" {
				d.Optional = managed.Optional
			}
		}
		m.dependencies = append(m.dependencies, d)
	}
	return m
}

var mavenPropertyRef = regexp.MustCompile(`\$\{([^}]+)\}`)

// interpolateMaven replaces ${property} references, following references
// inside property values. An unknown property is left as written, so it is
// recognisable in a report rather than silently becoming an empty string.
func interpolateMaven(s string, props map[string]string) string {
	for i := 0; i < 10 && strings.Contains(s, "${"); i++ {
		next := mavenPropertyRef.ReplaceAllStringFunc(s, func(ref string) string {
			if v, ok := props[ref[2:len(ref)-1]]; ok {
				return v
			}
			return ref
		})
		if next == s {
			break
		}
		s = next
	}
	return strings.TrimSpace(s)
}

// applyActiveProfiles folds in the profiles a scan can know are active: those
// active by default, and those activated by a property being absent
// ("!skipFoo"), since a scan sets no properties. Profiles keyed on the JDK, the
// operating system or a file depend on the build machine and are left out.
func applyActiveProfiles(pom *pomFile) {
	for _, profile := range pom.Profiles {
		active := strings.TrimSpace(profile.ActiveByDefault) == "true"
		if a := profile.Property; a != nil && strings.HasPrefix(strings.TrimSpace(a.Name), "!") {
			active = true
		}
		if !active {
			continue
		}
		if pom.Properties == nil {
			pom.Properties = make(pomProperties)
		}
		for k, v := range profile.Properties {
			pom.Properties[k] = v
		}
		pom.Management = append(pom.Management, profile.Management...)
		pom.Dependencies = append(pom.Dependencies, profile.Dependencies...)
	}
}

func readPOM(path string) (*pomFile, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}
	var pom pomFile
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = pomCharsetReader
	if err := decoder.Decode(&pom); err != nil {
		return nil, err
	}
	return &pom, nil
}

// pomCharsetReader lets a POM declare the encoding older ones commonly do,
// ISO-8859-1, which encoding/xml refuses outright — and with it the whole of
// junit 4's and hamcrest's corner of Maven Central. Latin-1 maps each byte to
// the code point of the same value, so the conversion needs no tables. Any
// other declared encoding is read as UTF-8: every element the parser reads is
// ASCII, so a stray accented byte in a description is the most it can cost.
func pomCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "l1", "windows-1252", "cp1252":
		data, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		runes := make([]rune, len(data))
		for i, b := range data {
			runes[i] = rune(b)
		}
		return strings.NewReader(string(runes)), nil
	}
	return input, nil
}

// indexReactor finds the modules of the multi-module build a POM belongs to,
// by climbing to the topmost parent that lives in the repository and
// descending through <modules> from there.
func (r *mavenResolver) indexReactor(file string) map[string]string {
	top := file
	for hops := 0; hops < maxPOMDepth; hops++ {
		pom, err := readPOM(top)
		if err != nil || pom.Parent == nil {
			break
		}
		rel := "../pom.xml"
		if pom.Parent.RelativePath != nil {
			rel = strings.TrimSpace(*pom.Parent.RelativePath)
		}
		if rel == "" {
			break
		}
		candidate := filepath.Join(filepath.Dir(top), filepath.FromSlash(rel))
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			candidate = filepath.Join(candidate, "pom.xml")
		}
		if parent, err := readPOM(candidate); err != nil || parent.ArtifactID != pom.Parent.ArtifactID {
			break
		}
		top = candidate
	}

	reactor := make(map[string]string)
	var visit func(string, int)
	visit = func(file string, depth int) {
		if depth > maxPOMDepth {
			return
		}
		pom, err := readPOM(file)
		if err != nil {
			return
		}
		group, version := pom.GroupID, pom.Version
		if pom.Parent != nil {
			if group == "" {
				group = pom.Parent.GroupID
			}
			if version == "" {
				version = pom.Parent.Version
			}
		}
		coords := group + ":" + pom.ArtifactID + ":" + interpolateMaven(version, pom.Properties)
		if _, seen := reactor[coords]; seen {
			return
		}
		reactor[coords] = file
		for _, module := range pom.Modules {
			child := filepath.Join(filepath.Dir(file), filepath.FromSlash(strings.TrimSpace(module)))
			if info, err := os.Stat(child); err == nil && info.IsDir() {
				child = filepath.Join(child, "pom.xml")
			}
			visit(child, depth+1)
		}
	}
	visit(top, 0)
	return reactor
}

// ---- local repository ----

// mavenLocalRepo is where Maven keeps downloaded artifacts: the
// maven.repo.local system property when MAVEN_OPTS sets it, then the
// <localRepository> of ~/.m2/settings.xml, then ~/.m2/repository.
func mavenLocalRepo() string {
	if opts := os.Getenv("MAVEN_OPTS"); opts != "" {
		for _, field := range strings.Fields(opts) {
			if v, ok := strings.CutPrefix(field, "-Dmaven.repo.local="); ok {
				return strings.Trim(v, `"'`)
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if data, err := readManifestFile(filepath.Join(home, ".m2", "settings.xml")); err == nil {
		var settings struct {
			LocalRepository string `xml:"localRepository"`
		}
		decoder := xml.NewDecoder(bytes.NewReader(data))
		decoder.CharsetReader = pomCharsetReader
		if decoder.Decode(&settings) == nil && strings.TrimSpace(settings.LocalRepository) != "" {
			return strings.ReplaceAll(strings.TrimSpace(settings.LocalRepository), "${user.home}", home)
		}
	}
	return filepath.Join(home, ".m2", "repository")
}

func mavenLocalRepoLocator(repo string) pomLocator {
	return func(groupID, artifactID, version string) string {
		if repo == "" || !safeMavenCoordinates(groupID, artifactID, version) {
			return ""
		}
		file := filepath.Join(repo, filepath.FromSlash(strings.ReplaceAll(groupID, ".", "/")), artifactID, version, artifactID+"-"+version+".pom")
		if version == "0" {
			// A probe for the artifact's directory, used to list versions.
			if _, err := os.Stat(filepath.Dir(filepath.Dir(file))); err == nil {
				return file
			}
			return ""
		}
		if _, err := os.Stat(file); err != nil {
			return ""
		}
		return file
	}
}

// ============= gradle =============

// GradleLockParser parses the gradle.lockfile Gradle writes when dependency
// locking is enabled: one line per resolved module, group:name:version, with
// the configurations it was resolved in.
//
// Like pubspec.lock it holds the full set at exact versions and no edges. The
// edges are in each module's POM, which Gradle keeps in its own cache —
// ~/.gradle/caches/modules-2 — and those are read where present, falling back
// to the Maven local repository, which Gradle builds often share. Which
// modules the project declared is read from build.gradle or build.gradle.kts
// beside the lockfile, where the coordinates appear as string literals.
type GradleLockParser struct{}

func (p *GradleLockParser) Name() string    { return "gradle (lockfile)" }
func (p *GradleLockParser) Files() []string { return []string{"gradle.lockfile"} }
func (p *GradleLockParser) Lockfile()       {}

func (p *GradleLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	type locked struct{ group, name, version string }
	var entries []locked
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coords, _, _ := strings.Cut(line, "=")
		parts := strings.Split(coords, ":")
		if len(parts) != 3 {
			continue
		}
		entries = append(entries, locked{parts[0], parts[1], parts[2]})
	}
	if len(entries) == 0 {
		return nil, nil
	}

	r := &mavenResolver{
		models:  make(map[string]*mavenModel),
		missing: make(map[string]bool),
		locate:  firstLocator(gradleCacheLocator(gradleUserHome()), mavenLocalRepoLocator(mavenLocalRepo())),
	}

	// Gradle can lock two versions of one module in different configurations
	// — a test classpath pinned apart from the runtime one — so a node is keyed
	// by version too, and an edge by name resolves only where the name is
	// unique, as for Cargo.
	nodes := make(map[string]node, len(entries))
	byName := make(map[string][]string)
	for _, e := range entries {
		name := e.group + ":" + e.name
		key := name + ":" + e.version
		deps := make(map[string]string)
		if model := r.modelFromRepo(e.group, e.name, e.version, 0); model != nil {
			for _, d := range model.dependencies {
				if d.Scope == "test" || d.Scope == "provided" || d.Scope == "system" || d.Optional == "true" {
					continue
				}
				deps[d.name()] = ""
			}
		}
		nodes[key] = node{name: name, version: e.version, deps: deps}
		byName[name] = append(byName[name], key)
	}

	resolve := func(_, name, _ string) (string, bool) {
		if keys := byName[name]; len(keys) == 1 {
			return keys[0], true
		}
		return "", false
	}
	roots := make(map[string]string)
	for name := range declaredInGradleBuild(filepath.Dir(path)) {
		if len(byName[name]) > 0 {
			roots[name] = ""
		}
	}
	return walkGraph(nodes, roots, resolve, "maven", path), nil
}

var gradleCoordinate = regexp.MustCompile(`["']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)(?::[^"'\s]*)?["']`)

// declaredInGradleBuild reads the group:name pairs a build script names as
// string literals. It errs towards finding too few: a coordinate built from a
// variable or a version catalog is not recognised, and that only loses the
// direct mark, never a package.
func declaredInGradleBuild(dir string) map[string]bool {
	declared := make(map[string]bool)
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		data, err := readManifestFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		for _, m := range gradleCoordinate.FindAllStringSubmatch(string(data), -1) {
			declared[m[1]+":"+m[2]] = true
		}
	}
	return declared
}

func gradleUserHome() string {
	if dir := os.Getenv("GRADLE_USER_HOME"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".gradle")
}

// gradleCacheLocator finds a POM in Gradle's cache, which files every artifact
// under a directory named for its checksum:
// caches/modules-2/files-2.1/<group>/<name>/<version>/<sha1>/<name>-<version>.pom.
func gradleCacheLocator(gradleHome string) pomLocator {
	return func(groupID, artifactID, version string) string {
		if gradleHome == "" || version == "0" || !safeMavenCoordinates(groupID, artifactID, version) {
			return ""
		}
		matches, _ := filepath.Glob(filepath.Join(gradleHome, "caches", "modules-2", "files-2.1", groupID, artifactID, version, "*", artifactID+"-"+version+".pom"))
		if len(matches) == 0 {
			return ""
		}
		sort.Strings(matches)
		return matches[0]
	}
}

// safeMavenCoordinates reports whether coordinates read from a POM can be
// turned into a path under a repository without leaving it. A groupId is dotted
// and becomes directories; none of the three may carry a separator, a ".." or
// an uninterpolated property.
func safeMavenCoordinates(groupID, artifactID, version string) bool {
	for _, s := range []string{groupID, artifactID, version} {
		if !safePathSegment(s) || strings.Contains(s, "${") || strings.Contains(s, "..") {
			return false
		}
	}
	return true
}

func firstLocator(locators ...pomLocator) pomLocator {
	return func(groupID, artifactID, version string) string {
		for _, locate := range locators {
			if file := locate(groupID, artifactID, version); file != "" {
				return file
			}
		}
		return ""
	}
}
