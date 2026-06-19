// Package config — loader.go 提供字典集合结构体与文件加载能力。
// 设计原则：所有字典都有 config.go 中的硬编码默认值作为 fallback，
// LoadDictSet 可从外部 txt 目录加载覆盖。
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DictSet 解耦后的完整字典集合，供整个扫描流水线引用。
type DictSet struct {
	// ── MCP ──
	MCPPorts       []int
	MCPEndpoints   []string
	SSELegacyPaths map[string]bool
	MCPAuthPaths   map[string]bool
	MCPServerHints []string
	HTTPSPorts     map[int]bool

	// ── A2A ──
	A2APorts     []int
	A2ACardPaths []string
}

// DefaultDictSet 返回代码内置的默认字典（deep copy，防止调用方误改全局值）。
func DefaultDictSet() *DictSet {
	return &DictSet{
		MCPPorts:       copyInts(DefaultPorts),
		MCPEndpoints:   copyStrings(MCPEndpoints),
		SSELegacyPaths: copyStringSet(SSELegacyPaths),
		MCPAuthPaths:   copyStringSet(MCPAuthPaths),
		MCPServerHints: copyStrings(MCPServerHints),
		HTTPSPorts:     copyIntSet(HTTPSPorts),
		A2APorts:       copyInts(A2ADefaultPorts),
		A2ACardPaths:   copyStrings(A2ACardPaths),
	}
}

// LoadDictSet 从指定目录加载字典文件。
//   - 文件不存在 → 静默 fallback 到默认值（正常用法）。
//   - 文件存在但解析出错 → 返回 error（用户配置有问题，应暴露）。
//   - dir 为空 → 直接返回 DefaultDictSet()。
func LoadDictSet(dir string) (*DictSet, error) {
	ds := DefaultDictSet()
	if dir == "" {
		return ds, nil
	}

	// Fail fast: if the caller supplied a non-empty dir that doesn't exist,
	// silently falling back to defaults would hide a misconfiguration.
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("dict-dir %q: %w", dir, err)
	}

	var errs []string

	// MCP 端口
	if ports, err := loadInts(filepath.Join(dir, "mcp_ports.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(ports) > 0 {
		ds.MCPPorts = dedupeInts(ports)
	}

	// MCP 端点路径
	if paths, err := loadStrings(filepath.Join(dir, "mcp_paths.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(paths) > 0 {
		ds.MCPEndpoints = normalizeAndDedupePaths(paths)
	}

	// SSE legacy 路径子集
	if paths, err := loadStrings(filepath.Join(dir, "mcp_paths_sse_legacy.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(paths) > 0 {
		ds.SSELegacyPaths = toStringSet(normalizeAndDedupePaths(paths))
	}

	// Auth 打分路径子集
	if paths, err := loadStrings(filepath.Join(dir, "mcp_paths_auth.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(paths) > 0 {
		ds.MCPAuthPaths = toStringSet(normalizeAndDedupePaths(paths))
	}

	// HTTP Server 头指纹词
	if hints, err := loadStrings(filepath.Join(dir, "http_server_hints.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(hints) > 0 {
		ds.MCPServerHints = normalizeAndDedupeHints(hints)
	}

	// HTTPS 端口
	if ports, err := loadInts(filepath.Join(dir, "https_ports.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(ports) > 0 {
		ds.HTTPSPorts = toIntSet(dedupeInts(ports))
	}

	// A2A 端口
	if ports, err := loadInts(filepath.Join(dir, "a2a_ports.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(ports) > 0 {
		ds.A2APorts = dedupeInts(ports)
	}

	// A2A Card 路径
	if paths, err := loadStrings(filepath.Join(dir, "a2a_paths.txt")); err != nil {
		if !isNotFound(err) {
			errs = append(errs, err.Error())
		}
	} else if len(paths) > 0 {
		ds.A2ACardPaths = normalizeAndDedupePaths(paths)
	}

	if len(errs) > 0 {
		return ds, fmt.Errorf("dict-dir %q: %s", dir, strings.Join(errs, "; "))
	}
	return ds, nil
}

// ── 内部加载函数 ──────────────────────────────────────────────────────────────

// loadStrings 从 txt 文件加载字符串列表。
// 格式：每行一个值，# 开头为注释，空行跳过。
// 文件不存在返回 *os.PathError（调用方可用 isNotFound 检测）。
// 文件存在但 scan 出错返回带文件名上下文的 error。
func loadStrings(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err // preserve *os.PathError for isNotFound check
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return lines, nil
}

// loadInts 从 txt 文件加载端口整数列表。
// 非法行（非整数或范围外）打印警告并跳过，不返回 error。
// 文件不存在返回 *os.PathError；文件格式问题仅 warn，不 error。
func loadInts(path string) ([]int, error) {
	lines, err := loadStrings(path)
	if err != nil {
		return nil, err
	}
	var nums []int
	for i, l := range lines {
		n, convErr := strconv.Atoi(l)
		if convErr != nil {
			fmt.Fprintf(os.Stderr, "[WARN] %s line %d: invalid integer %q\n", path, i+1, l)
			continue
		}
		if n < 1 || n > 65535 {
			fmt.Fprintf(os.Stderr, "[WARN] %s line %d: port %d out of range (1-65535), skipped\n", path, i+1, n)
			continue
		}
		nums = append(nums, n)
	}
	return nums, nil
}

// isNotFound reports whether err indicates a missing file.
func isNotFound(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// ── Normalize / dedupe helpers ────────────────────────────────────────────────

// normalizeAndDedupePaths ensures each path is non-empty, starts with '/',
// and deduplicates while preserving order.
func normalizeAndDedupePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if _, exists := seen[p]; exists {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// normalizeAndDedupeHints lowercases hints and deduplicates while preserving order.
func normalizeAndDedupeHints(hints []string) []string {
	seen := make(map[string]struct{}, len(hints))
	out := make([]string, 0, len(hints))
	for _, h := range hints {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, exists := seen[h]; exists {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

// dedupeInts removes duplicate integers while preserving order.
func dedupeInts(ns []int) []int {
	seen := make(map[int]struct{}, len(ns))
	out := make([]int, 0, len(ns))
	for _, n := range ns {
		if _, exists := seen[n]; exists {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func toStringSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func toIntSet(ns []int) map[int]bool {
	m := make(map[int]bool, len(ns))
	for _, n := range ns {
		m[n] = true
	}
	return m
}

// ── Deep-copy helpers (prevent global mutation) ───────────────────────────────

func copyStrings(src []string) []string {
	if src == nil {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

func copyInts(src []int) []int {
	if src == nil {
		return nil
	}
	dst := make([]int, len(src))
	copy(dst, src)
	return dst
}

func copyStringSet(src map[string]bool) map[string]bool {
	if src == nil {
		return nil
	}
	dst := make(map[string]bool, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func copyIntSet(src map[int]bool) map[int]bool {
	if src == nil {
		return nil
	}
	dst := make(map[int]bool, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
