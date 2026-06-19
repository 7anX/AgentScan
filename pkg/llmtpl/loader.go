package llmtpl

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed templates/llm/*.yaml
var embeddedTemplates embed.FS

// LoadTemplates loads all LLM templates from the embedded FS, then overlays
// any templates from userDir (if non-empty). User templates with the same
// info.name override embedded ones.
func LoadTemplates(userDir string) ([]*Template, error) {
	// Load embedded defaults
	templates, err := loadTemplatesFromFS(embeddedTemplates, "templates/llm")
	if err != nil {
		return nil, fmt.Errorf("load embedded templates: %w", err)
	}

	// Overlay user templates if specified
	if userDir != "" {
		userTemplates, err := loadTemplatesFromDir(userDir)
		if err != nil {
			return nil, fmt.Errorf("load user templates from %s: %w", userDir, err)
		}
		templates = mergeTemplates(templates, userTemplates)
	}

	// Validate all templates
	for _, t := range templates {
		if err := ValidateTemplate(t); err != nil {
			return nil, fmt.Errorf("validate template %q: %w", t.Info.Name, err)
		}
	}

	return templates, nil
}

// LoadTemplatesFromDir loads templates from a filesystem directory only (no embed).
// Useful for testing or standalone use.
func LoadTemplatesFromDir(dir string) ([]*Template, error) {
	templates, err := loadTemplatesFromDir(dir)
	if err != nil {
		return nil, err
	}
	for _, t := range templates {
		if err := ValidateTemplate(t); err != nil {
			return nil, fmt.Errorf("validate template %q: %w", t.Info.Name, err)
		}
	}
	return templates, nil
}

// ParseTemplate parses a single YAML byte slice into a Template.
func ParseTemplate(data []byte) (*Template, error) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// ValidateTemplate checks a template for structural errors.
func ValidateTemplate(t *Template) error {
	if t.Info.Name == "" {
		return fmt.Errorf("info.name is required")
	}
	if len(t.HTTP) == 0 {
		return fmt.Errorf("at least one http rule is required")
	}
	for i, rule := range t.HTTP {
		if rule.Path == "" {
			return fmt.Errorf("http[%d].path is required", i)
		}
		if len(rule.Matchers) == 0 {
			return fmt.Errorf("http[%d].matchers is required", i)
		}
		for j, m := range rule.Matchers {
			if _, err := CompileRule(m); err != nil {
				return fmt.Errorf("http[%d].matchers[%d]: %w", i, j, err)
			}
		}
	}
	for i, rule := range t.Stage2 {
		if rule.Path == "" {
			return fmt.Errorf("stage2[%d].path is required", i)
		}
		for j, m := range rule.Matchers {
			if _, err := CompileRule(m); err != nil {
				return fmt.Errorf("stage2[%d].matchers[%d]: %w", i, j, err)
			}
		}
	}
	for i, neg := range t.Negatives {
		if _, err := CompileRule(neg); err != nil {
			return fmt.Errorf("negatives[%d]: %w", i, err)
		}
	}
	return nil
}

// ─── Internal helpers ───────────────────────────────────────────────────────

func loadTemplatesFromFS(fsys fs.FS, dir string) ([]*Template, error) {
	var templates []*Template

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isYAMLFile(entry.Name()) {
			continue
		}
		data, err := fs.ReadFile(fsys, filepath.ToSlash(filepath.Join(dir, entry.Name())))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		t, err := ParseTemplate(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		templates = append(templates, t)
	}

	return templates, nil
}

func loadTemplatesFromDir(dir string) ([]*Template, error) {
	var templates []*Template

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isYAMLFile(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		t, err := ParseTemplate(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		templates = append(templates, t)
	}

	return templates, nil
}

// mergeTemplates overlays user templates on top of base templates.
// User templates with the same info.name replace the base template entirely.
func mergeTemplates(base, overlay []*Template) []*Template {
	nameMap := make(map[string]int, len(base))
	for i, t := range base {
		nameMap[strings.ToLower(t.Info.Name)] = i
	}

	for _, t := range overlay {
		key := strings.ToLower(t.Info.Name)
		if idx, exists := nameMap[key]; exists {
			base[idx] = t // replace
		} else {
			base = append(base, t) // add new
		}
	}

	return base
}

func isYAMLFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
