package sca

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The fixture under testdata/maven/project is a two-module Maven build — a
// parent aggregating fixture-core and fixture-app, where the app depends on
// the core — built with
//
//	mvn -Dmaven.repo.local=$PWD/repository install
//
// The POMs are committed verbatim. testdata/maven/repository holds, verbatim
// and at their local-repository paths, only the POMs resolving the build
// reads: the dependencies' own, their parents and the jackson BOM. The
// expectations below are `mvn dependency:tree` for the same modules, which the
// resolver matches artifact for artifact, version for version and parent for
// parent. The same comparison was run against a Spring Boot 2.5 application
// (102 artifacts) and a Hadoop 3.3 / AWS SDK / netty one (130).
//
// The fixture exercises each rule the resolution depends on: a version from a
// BOM imported by the parent, through a parent property; the parent's
// dependency management overriding a transitive version (commons-codec 1.13
// where httpclient asks for 1.11); an exclusion (commons-logging); optional and
// test-scoped direct dependencies; a sibling module; and POMs in ISO-8859-1.
const mavenFixture = "testdata/maven"

func mavenFixtureRepo(t *testing.T) {
	t.Helper()
	repo, err := filepath.Abs(filepath.Join(mavenFixture, "repository"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAVEN_OPTS", "-Xmx1g -Dmaven.repo.local="+repo)
}

func TestMavenResolvesTheTree(t *testing.T) {
	mavenFixtureRepo(t)

	parser := &PomXMLParser{}
	deps, err := parser.Parse(filepath.Join(mavenFixture, "project", "app", "pom.xml"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	type want struct {
		version string
		direct  bool
		path    []string
	}
	const core = "com.example.drogonsec:fixture-core"
	expected := map[string]want{
		"com.fasterxml.jackson.core:jackson-databind":    {"2.9.10", true, nil},
		"com.fasterxml.jackson.core:jackson-annotations": {"2.9.10", false, []string{"com.fasterxml.jackson.core:jackson-databind"}},
		"com.fasterxml.jackson.core:jackson-core":        {"2.9.10", false, []string{"com.fasterxml.jackson.core:jackson-databind"}},
		"org.apache.httpcomponents:httpclient":           {"4.5.13", true, nil},
		"org.apache.httpcomponents:httpcore":             {"4.4.13", false, []string{"org.apache.httpcomponents:httpclient"}},
		"commons-codec:commons-codec":                    {"1.13", false, []string{"org.apache.httpcomponents:httpclient"}},
		"org.yaml:snakeyaml":                             {"1.26", true, nil},
		"junit:junit":                                    {"4.12", true, nil},
		"org.hamcrest:hamcrest-core":                     {"1.3", false, []string{"junit:junit"}},
		"org.apache.logging.log4j:log4j-core":            {"2.14.1", false, []string{core}},
		"org.apache.logging.log4j:log4j-api":             {"2.14.1", false, []string{core, "org.apache.logging.log4j:log4j-core"}},
		"org.apache.commons:commons-text":                {"1.9", false, []string{core}},
		"org.apache.commons:commons-lang3":               {"3.11", false, []string{core, "org.apache.commons:commons-text"}},
	}

	if len(deps) != len(expected) {
		t.Errorf("resolved %d artifacts, want %d: %v", len(deps), len(expected), depNames(deps))
	}
	for _, d := range deps {
		w, ok := expected[d.Name]
		if !ok {
			t.Errorf("unexpected artifact %s:%s", d.Name, d.Version)
			continue
		}
		if d.Version != w.version {
			t.Errorf("%s version = %s, want %s", d.Name, d.Version, w.version)
		}
		if d.Direct != w.direct {
			t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, w.direct)
		}
		if !reflect.DeepEqual(d.Path, w.path) {
			t.Errorf("%s route = %v, want %v", d.Name, d.Path, w.path)
		}
		if d.Ecosystem != "maven" || d.VersionIsRange {
			t.Errorf("%s ecosystem=%s range=%v", d.Name, d.Ecosystem, d.VersionIsRange)
		}
	}

	t.Run("an excluded artifact is not resolved", func(t *testing.T) {
		if _, ok := findDep(deps, "commons-logging:commons-logging"); ok {
			t.Error("commons-logging is excluded from httpclient and must not appear")
		}
	})

	t.Run("a sibling module is the project's own code", func(t *testing.T) {
		if _, ok := findDep(deps, core); ok {
			t.Error("fixture-core was reported as a dependency of the build it belongs to")
		}
	})

	t.Run("edges reach the SBOM", func(t *testing.T) {
		d, _ := findDep(deps, "org.apache.httpcomponents:httpclient")
		want := []Ref{
			{Name: "org.apache.httpcomponents:httpcore", Version: "4.4.13"},
			{Name: "commons-codec:commons-codec", Version: "1.13"},
		}
		if !reflect.DeepEqual(d.Requires, want) {
			t.Errorf("httpclient requires %v, want %v", d.Requires, want)
		}
	})

	t.Run("nothing is missing from the fixture repository", func(t *testing.T) {
		if notes := parser.notes(); len(notes) != 0 {
			t.Errorf("unexpected notes: %v", notes)
		}
	})
}

func TestMavenModuleDeclaringItsOwnDependencies(t *testing.T) {
	mavenFixtureRepo(t)

	deps, err := (&PomXMLParser{}).Parse(filepath.Join(mavenFixture, "project", "core", "pom.xml"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	want := []string{
		"org.apache.commons:commons-lang3", "org.apache.commons:commons-text",
		"org.apache.logging.log4j:log4j-api", "org.apache.logging.log4j:log4j-core",
	}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("resolved %v, want %v", got, want)
	}
	log4j, _ := findDep(deps, "org.apache.logging.log4j:log4j-core")
	if !log4j.Direct || log4j.Version != "2.14.1" {
		t.Errorf("log4j-core = %s direct=%v, want 2.14.1 from the parent's property, direct", log4j.Version, log4j.Direct)
	}
}

// TestMavenWithoutLocalRepository covers a project that has never been built
// on the scanning machine. The declared artifacts whose version the POM itself
// determines are still reported, the ones needing a BOM that is not there are
// not, and the scan says what it could not see.
func TestMavenWithoutLocalRepository(t *testing.T) {
	t.Setenv("MAVEN_OPTS", "-Dmaven.repo.local="+t.TempDir())

	parser := &PomXMLParser{}
	deps, err := parser.Parse(filepath.Join(mavenFixture, "project", "app", "pom.xml"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// jackson-databind takes its version from the jackson BOM, which is not
	// available; fixture-core is in the repository and still walked.
	want := []string{
		"junit:junit",
		"org.apache.commons:commons-text",
		"org.apache.httpcomponents:httpclient",
		"org.apache.logging.log4j:log4j-core",
		"org.yaml:snakeyaml",
	}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("resolved %v, want %v", got, want)
	}
	notes := parser.notes()
	if len(notes) != 1 || !strings.Contains(notes[0], "not in the local repository") {
		t.Errorf("notes = %v, want one saying POMs were missing", notes)
	}
}

func TestMavenAggregatorHasNoDependencies(t *testing.T) {
	mavenFixtureRepo(t)

	deps, err := (&PomXMLParser{}).Parse(filepath.Join(mavenFixture, "project", "pom.xml"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("the aggregator declares no dependencies, got %v", depNames(deps))
	}
}

// TestMavenRelocationAndRange uses a hand-built repository for the two rules
// the committed fixture does not reach.
func TestMavenRelocationAndRange(t *testing.T) {
	repo := t.TempDir()
	t.Setenv("MAVEN_OPTS", "-Dmaven.repo.local="+repo)

	pom := func(g, a, v, body string) {
		writeFile(t, filepath.Join(repo, strings.ReplaceAll(g, ".", "/"), a, v, a+"-"+v+".pom"),
			`<project><groupId>`+g+`</groupId><artifactId>`+a+`</artifactId><version>`+v+`</version>`+body+`</project>`)
	}
	// mysql-connector-java moved to com.mysql:mysql-connector-j, and its
	// POM says so rather than listing dependencies.
	pom("mysql", "mysql-connector-java", "8.0.33", `<distributionManagement><relocation><groupId>com.mysql</groupId><artifactId>mysql-connector-j</artifactId></relocation></distributionManagement>`)
	pom("com.mysql", "mysql-connector-j", "8.0.33", `<dependencies><dependency><groupId>com.google.protobuf</groupId><artifactId>protobuf-java</artifactId><version>3.21.9</version></dependency></dependencies>`)
	pom("com.google.protobuf", "protobuf-java", "3.21.9", "")
	for _, v := range []string{"2.8.5", "2.8.9", "2.9.0"} {
		pom("com.google.code.gson", "gson", v, "")
	}

	project := filepath.Join(t.TempDir(), "pom.xml")
	writeFile(t, project, `<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>mysql</groupId><artifactId>mysql-connector-java</artifactId><version>8.0.33</version></dependency>
    <dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>[2.8,2.9)</version></dependency>
    <dependency><groupId>org.unknown</groupId><artifactId>ranged</artifactId><version>[1.0,)</version></dependency>
  </dependencies>
</project>`)

	deps, err := (&PomXMLParser{}).Parse(project)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if _, ok := findDep(deps, "mysql:mysql-connector-java"); ok {
		t.Error("the relocated coordinates were reported instead of the new ones")
	}
	if d, ok := findDep(deps, "com.mysql:mysql-connector-j"); !ok || d.Version != "8.0.33" || !d.Direct {
		t.Errorf("relocation not followed: %+v", d)
	}
	if d, ok := findDep(deps, "com.google.protobuf:protobuf-java"); !ok || !reflect.DeepEqual(d.Path, []string{"com.mysql:mysql-connector-j"}) {
		t.Errorf("the relocated artifact's dependencies were not walked: %+v", d)
	}
	if d, _ := findDep(deps, "com.google.code.gson:gson"); d.Version != "2.8.9" || d.VersionIsRange {
		t.Errorf("gson = %s range=%v, want the highest local version in range, 2.8.9", d.Version, d.VersionIsRange)
	}
	if d, _ := findDep(deps, "org.unknown:ranged"); !d.VersionIsRange {
		t.Error("a range nothing in the local repository satisfies must stay a range and not be matched")
	}
}

func TestMavenRangeContains(t *testing.T) {
	tests := []struct {
		spec, version string
		want          bool
	}{
		{"[1.0,2.0)", "1.5", true},
		{"[1.0,2.0)", "2.0", false},
		{"[1.0,2.0]", "2.0", true},
		{"(1.0,2.0)", "1.0", false},
		{"[1.2]", "1.2", true},
		{"(,1.5]", "0.9", true},
		{"[3.0,)", "4.1", true},
		{"[1.0,1.2),[1.3,)", "1.2.5", false},
		{"[1.0,1.2),[1.3,)", "1.4", true},
	}
	for _, tt := range tests {
		if got := mavenRangeContains(tt.spec, tt.version); got != tt.want {
			t.Errorf("mavenRangeContains(%q, %q) = %v, want %v", tt.spec, tt.version, got, tt.want)
		}
	}
}

func TestInterpolateMaven(t *testing.T) {
	props := map[string]string{"a": "${b}", "b": "1.2", "project.version": "3.0"}
	if got := interpolateMaven("${a}-${project.version}", props); got != "1.2-3.0" {
		t.Errorf("got %q", got)
	}
	if got := interpolateMaven("${unknown}", props); got != "${unknown}" {
		t.Errorf("an unknown property must be left as written, got %q", got)
	}
}

// The fixture under testdata/gradle was produced by Gradle itself, from the
// build.gradle.kts beside it, with dependency locking on for every
// configuration:
//
//	GRADLE_USER_HOME=$PWD/gradle-home gradle dependencies --write-locks
//
// gradle.lockfile is committed verbatim, and gradle-home holds the POMs Gradle
// downloaded, at the paths it stored them, and nothing else.
const gradleFixture = "testdata/gradle"

func TestGradleLockfile(t *testing.T) {
	home, err := filepath.Abs(filepath.Join(gradleFixture, "gradle-home"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRADLE_USER_HOME", home)
	t.Setenv("MAVEN_OPTS", "-Dmaven.repo.local="+t.TempDir())

	deps, err := (&GradleLockParser{}).Parse(filepath.Join(gradleFixture, "gradle.lockfile"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(deps) != 9 {
		t.Errorf("parsed %d modules, want 9: %v", len(deps), depNames(deps))
	}

	direct := map[string]bool{
		"org.apache.logging.log4j:log4j-core": true,
		"com.squareup.okhttp3:okhttp":         true,
		"junit:junit":                         true,
	}
	for _, d := range deps {
		if d.Direct != direct[d.Name] {
			t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
		}
		if d.Ecosystem != "maven" {
			t.Errorf("%s ecosystem = %s, want maven", d.Name, d.Ecosystem)
		}
	}

	// Each route is the shortest one `gradle dependencies` shows: okio pulls in
	// kotlin-stdlib-common directly, one hop before kotlin-stdlib would.
	routes := map[string][]string{
		"com.squareup.okio:okio":                    {"com.squareup.okhttp3:okhttp"},
		"org.jetbrains.kotlin:kotlin-stdlib":        {"com.squareup.okhttp3:okhttp"},
		"org.jetbrains:annotations":                 {"com.squareup.okhttp3:okhttp", "org.jetbrains.kotlin:kotlin-stdlib"},
		"org.apache.logging.log4j:log4j-api":        {"org.apache.logging.log4j:log4j-core"},
		"org.hamcrest:hamcrest-core":                {"junit:junit"},
		"org.jetbrains.kotlin:kotlin-stdlib-common": {"com.squareup.okhttp3:okhttp", "com.squareup.okio:okio"},
	}
	for name, route := range routes {
		d, ok := findDep(deps, name)
		if !ok {
			t.Errorf("%s missing", name)
			continue
		}
		if !reflect.DeepEqual(d.Path, route) {
			t.Errorf("%s route = %v, want %v", name, d.Path, route)
		}
	}
}

// TestEngineReadsJavaAndDart runs the whole collection over the fixtures, so
// the parsers are known to be registered and to win over the manifests beside
// them.
func TestEngineReadsJavaAndDart(t *testing.T) {
	mavenFixtureRepo(t)
	home, _ := filepath.Abs(filepath.Join(gradleFixture, "gradle-home"))
	t.Setenv("GRADLE_USER_HOME", home)

	deps, err := New(gradleFixture).collectDependencies()
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 9 {
		t.Errorf("gradle fixture: %d dependencies, want 9", len(deps))
	}

	deps, err = New(filepath.Join(mavenFixture, "project")).collectDependencies()
	if err != nil {
		t.Fatal(err)
	}
	// app resolves 13 artifacts and core 4; the aggregator none.
	if len(deps) != 17 {
		t.Errorf("maven fixture: %d dependencies, want 17", len(deps))
	}
}
