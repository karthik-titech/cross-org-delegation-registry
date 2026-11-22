package pedigree

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const vectorPath = "vectors/pedigree-01"

// DefaultVectorDir locates the vector directory from the repository or module root.
func DefaultVectorDir() string {
	if _, err := os.Stat("reference/go/go.mod"); err == nil {
		return vectorPath
	}
	return filepath.Join("..", "..", vectorPath)
}

type pinnedResult struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Index  int    `json:"presentation"`
	Result
}

type cliResult struct {
	ID                string   `json:"id"`
	Index             int      `json:"presentation"`
	Expected          string   `json:"expected"`
	Got               string   `json:"got"`
	TrustedInputsUsed []string `json:"trusted_inputs_used"`
	Status            string   `json:"status"`
}

// RunVectors verifies each presentation against the pinned outcomes and writes
// one JSON report per verified presentation. Each case has independent replay state.
func RunVectors(dir string, out io.Writer) error {
	f, err := loadFixtureSpec()
	if err != nil {
		return err
	}
	groups, ids, err := readPinned(dir)
	if err != nil {
		return err
	}
	if err := checkCaseFiles(dir, groups); err != nil {
		return err
	}
	var failures []string
	encoder := json.NewEncoder(out)
	for _, id := range ids {
		if err := runVector(dir, id, groups[id], f, encoder); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("%s", strings.Join(failures, "\n"))
	}
	return nil
}

func readPinned(dir string) (map[string][]pinnedResult, []string, error) {
	var table struct {
		Cases []pinnedResult `json:"cases"`
	}
	if err := readVector(filepath.Join(dir, "expected.json"), &table); err != nil {
		return nil, nil, err
	}
	if len(table.Cases) == 0 {
		return nil, nil, fmt.Errorf("expected.json has no cases")
	}
	groups := make(map[string][]pinnedResult)
	var ids []string
	for _, pin := range table.Cases {
		if !validCaseID(pin.ID) || pin.Source != "appendix_a" && pin.Source != "local" ||
			pin.Index <= 0 || pin.Outcome == "" || pin.TrustedInputsUsed == nil {
			return nil, nil, fmt.Errorf("invalid pinned row for %q presentation %d", pin.ID, pin.Index)
		}
		if groups[pin.ID] == nil {
			ids = append(ids, pin.ID)
		}
		groups[pin.ID] = append(groups[pin.ID], pin)
	}
	for _, id := range ids {
		pins := groups[id]
		slices.SortFunc(pins, func(a, b pinnedResult) int { return a.Index - b.Index })
		for i, pin := range pins {
			if pin.Index != i+1 || pin.Source != pins[0].Source {
				return nil, nil, fmt.Errorf("inconsistent pinned rows for %s", id)
			}
		}
	}
	return groups, ids, nil
}

func validCaseID(id string) bool {
	if id == "" || id == "manifest" || id == "expected" {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func checkCaseFiles(dir string, groups map[string][]pinnedResult) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range files {
		name := entry.Name()
		id := strings.TrimSuffix(name, ".json")
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".json") ||
			(id != "expected" && id != "manifest" && groups[id] == nil) {
			return fmt.Errorf("unexpected vector directory entry %q", name)
		}
		seen[id] = true
	}
	if !seen["expected"] || !seen["manifest"] {
		return fmt.Errorf("missing expected.json or manifest.json")
	}
	for id := range groups {
		if !seen[id] {
			return fmt.Errorf("missing case file %s.json", id)
		}
	}
	return nil
}

func readVector(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%s: trailing JSON input", path)
	}
	return nil
}

func runVector(dir, id string, pins []pinnedResult, f fixtureSpec, encoder *json.Encoder) error {
	var c fixtureCase
	if err := readVector(filepath.Join(dir, id+".json"), &c); err != nil {
		return err
	}
	if c.ID != id || c.Source != pins[0].Source || len(c.Presentations) != len(pins) {
		return fmt.Errorf("%s: case metadata does not match expected.json", id)
	}
	wpts, err := c.assumptions()
	if err != nil {
		return err
	}
	cfg, err := c.config(f)
	if err != nil {
		return err
	}
	failed := false
	for i, pin := range pins {
		p := c.Presentations[i]
		got := Verify(p.Presentation, Trusted{WPT: wpts[i], Consent: c.Consent, Policies: f.FixturePolicies}, cfg, c.At)
		status := "PASS"
		if !matchResult(got, pin.Result) || !matchResult(p.Result, pin.Result) {
			status = "FAIL"
			failed = true
		}
		r := cliResult{id, pin.Index, pin.Outcome, got.Outcome, got.TrustedInputsUsed, status}
		if err := encoder.Encode(r); err != nil {
			return err
		}
	}
	if failed {
		return fmt.Errorf("%s: a result differs from expected.json", id)
	}
	return nil
}

func (c fixtureCase) assumptions() ([]WPTAssumption, error) {
	n := len(c.Presentations)
	if len(c.WPT) != n {
		return nil, fmt.Errorf("%s: expected one WPT assumption per presentation", c.ID)
	}
	wpts := make([]WPTAssumption, n)
	for _, wpt := range c.WPT {
		i := wpt.PresentationIndex
		if i < 1 || i > n || wpts[i-1].PresentationIndex != 0 {
			return nil, fmt.Errorf("%s: invalid or duplicate WPT presentation index %d", c.ID, i)
		}
		wpts[i-1] = wpt
	}
	return wpts, nil
}

func matchResult(got, want Result) bool {
	return got.Outcome == want.Outcome && got.TrustedInputsUsed != nil &&
		slices.Equal(got.TrustedInputsUsed, want.TrustedInputsUsed)
}
