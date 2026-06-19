// Package llmtpl implements a YAML-template-driven LLM framework detection engine.
//
// The DSL expression engine is inspired by AI-Infra-Guard's fingerprint parser
// but reimplemented from scratch for AgentScan's LLM probe use case.
package llmtpl

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ─── Token types ────────────────────────────────────────────────────────────

const (
	tokBody    = "body"
	tokHeader  = "header"
	tokStatus  = "status"
	tokEq      = "="  // contains
	tokExact   = "==" // exact match
	tokNotEq   = "!=" // not contains
	tokRegex   = "~=" // regex match
	tokAnd     = "&&"
	tokOr      = "||"
	tokLParen  = "("
	tokRParen  = ")"
	tokLiteral = "LITERAL" // quoted string value
)

// token represents a single lexical unit in a DSL expression.
type token struct {
	typ string
	val string // for tokLiteral: the unquoted content
}

// ─── Lexer ──────────────────────────────────────────────────────────────────

// tokenize splits a DSL expression string into tokens.
//
// Grammar:
//
//	expr     = term (("&&" | "||") term)*
//	term     = "(" expr ")" | field op literal
//	field    = "body" | "header" | "status"
//	op       = "=" | "==" | "!=" | "~="
//	literal  = '"' chars '"'
func tokenize(expr string) ([]token, error) {
	var tokens []token
	i := 0
	n := len(expr)

	for i < n {
		// Skip whitespace
		if unicode.IsSpace(rune(expr[i])) {
			i++
			continue
		}

		// Parentheses
		if expr[i] == '(' {
			tokens = append(tokens, token{typ: tokLParen, val: "("})
			i++
			continue
		}
		if expr[i] == ')' {
			tokens = append(tokens, token{typ: tokRParen, val: ")"})
			i++
			continue
		}

		// Operators: &&, ||, ==, !=, ~=, =
		if i+1 < n {
			two := expr[i : i+2]
			switch two {
			case "&&":
				tokens = append(tokens, token{typ: tokAnd, val: "&&"})
				i += 2
				continue
			case "||":
				tokens = append(tokens, token{typ: tokOr, val: "||"})
				i += 2
				continue
			case "==":
				tokens = append(tokens, token{typ: tokExact, val: "=="})
				i += 2
				continue
			case "!=":
				tokens = append(tokens, token{typ: tokNotEq, val: "!="})
				i += 2
				continue
			case "~=":
				tokens = append(tokens, token{typ: tokRegex, val: "~="})
				i += 2
				continue
			}
		}

		// Single = (contains)
		if expr[i] == '=' {
			tokens = append(tokens, token{typ: tokEq, val: "="})
			i++
			continue
		}

		// Quoted string literal
		if expr[i] == '"' {
			end := i + 1
			for end < n {
				if expr[end] == '\\' && end+1 < n {
					end += 2 // skip escaped character
					continue
				}
				if expr[end] == '"' {
					break
				}
				end++
			}
			if end >= n {
				return nil, fmt.Errorf("unterminated string at position %d", i)
			}
			// Unescape the content
			raw := expr[i+1 : end]
			val := unescapeString(raw)
			tokens = append(tokens, token{typ: tokLiteral, val: val})
			i = end + 1
			continue
		}

		// Keywords: body, header, status
		if i+6 <= n && expr[i:i+6] == "header" && (i+6 >= n || !isIdentChar(expr[i+6])) {
			tokens = append(tokens, token{typ: tokHeader, val: "header"})
			i += 6
			continue
		}
		if i+6 <= n && expr[i:i+6] == "status" && (i+6 >= n || !isIdentChar(expr[i+6])) {
			tokens = append(tokens, token{typ: tokStatus, val: "status"})
			i += 6
			continue
		}
		if i+4 <= n && expr[i:i+4] == "body" && (i+4 >= n || !isIdentChar(expr[i+4])) {
			tokens = append(tokens, token{typ: tokBody, val: "body"})
			i += 4
			continue
		}

		return nil, fmt.Errorf("unexpected character %q at position %d", expr[i], i)
	}

	return tokens, nil
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func unescapeString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			default:
				b.WriteByte('\\')
				b.WriteByte(s[i])
			}
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// ─── AST ────────────────────────────────────────────────────────────────────

// dslNode is the interface for AST nodes.
type dslNode interface {
	eval(cfg *MatchConfig) bool
}

// compareNode: field op literal
type compareNode struct {
	field string // "body" | "header" | "status"
	op    string // "=" | "==" | "!=" | "~="
	value string // the literal value
	regex *regexp.Regexp
}

func (c *compareNode) eval(cfg *MatchConfig) bool {
	var target string
	switch c.field {
	case tokBody:
		target = cfg.Body
	case tokHeader:
		target = cfg.Header
	case tokStatus:
		target = cfg.StatusCode
	default:
		return false
	}

	// Case-insensitive comparison
	targetLower := strings.ToLower(target)
	valueLower := strings.ToLower(c.value)

	switch c.op {
	case tokEq: // contains
		return strings.Contains(targetLower, valueLower)
	case tokExact: // exact match
		return targetLower == valueLower
	case tokNotEq: // not contains
		return !strings.Contains(targetLower, valueLower)
	case tokRegex: // regex match
		if c.regex != nil {
			return c.regex.MatchString(targetLower)
		}
		return false
	default:
		return false
	}
}

// logicNode: left op right
type logicNode struct {
	op    string // "&&" | "||"
	left  dslNode
	right dslNode
}

func (l *logicNode) eval(cfg *MatchConfig) bool {
	switch l.op {
	case tokAnd:
		if !l.left.eval(cfg) {
			return false // short-circuit
		}
		return l.right.eval(cfg)
	case tokOr:
		if l.left.eval(cfg) {
			return true // short-circuit
		}
		return l.right.eval(cfg)
	default:
		return false
	}
}

// ─── Parser ─────────────────────────────────────────────────────────────────

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.pos]
}

func (p *parser) next() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	t := &p.tokens[p.pos]
	p.pos++
	return t
}

// parseExpr handles: term (("&&" | "||") term)*
func (p *parser) parseExpr() (dslNode, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}

	for {
		t := p.peek()
		if t == nil {
			break
		}
		if t.typ != tokAnd && t.typ != tokOr {
			break
		}
		op := p.next()
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		left = &logicNode{op: op.typ, left: left, right: right}
	}

	return left, nil
}

// parseTerm handles: "(" expr ")" | field op literal
func (p *parser) parseTerm() (dslNode, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("unexpected end of expression")
	}

	// Parenthesized expression
	if t.typ == tokLParen {
		p.next() // consume "("
		node, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		closing := p.next()
		if closing == nil || closing.typ != tokRParen {
			return nil, fmt.Errorf("expected ')' but got %v", closing)
		}
		return node, nil
	}

	// field op literal
	if t.typ == tokBody || t.typ == tokHeader || t.typ == tokStatus {
		field := p.next()
		opTok := p.next()
		if opTok == nil {
			return nil, fmt.Errorf("expected operator after %q", field.val)
		}
		if opTok.typ != tokEq && opTok.typ != tokExact && opTok.typ != tokNotEq && opTok.typ != tokRegex {
			return nil, fmt.Errorf("unexpected operator %q after %q", opTok.val, field.val)
		}
		litTok := p.next()
		if litTok == nil || litTok.typ != tokLiteral {
			return nil, fmt.Errorf("expected quoted string after operator")
		}

		node := &compareNode{
			field: field.typ,
			op:    opTok.typ,
			value: litTok.val,
		}

		// Pre-compile regex
		if opTok.typ == tokRegex {
			re, err := regexp.Compile("(?i)" + litTok.val)
			if err != nil {
				return nil, fmt.Errorf("invalid regex %q: %w", litTok.val, err)
			}
			node.regex = re
		}

		return node, nil
	}

	return nil, fmt.Errorf("unexpected token %q at position %d", t.val, p.pos)
}

// ─── Public API ─────────────────────────────────────────────────────────────

// MatchConfig holds the HTTP response data for matcher evaluation.
type MatchConfig struct {
	Body       string // response body (original case, lowercased during eval)
	Header     string // raw response headers as string
	StatusCode string // HTTP status code as string (e.g. "200")
}

// Rule is a compiled DSL expression ready for evaluation.
type Rule struct {
	raw  string
	root dslNode
}

// CompileRule parses and compiles a DSL expression string into a Rule.
func CompileRule(expr string) (*Rule, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty expression")
	}

	tokens, err := tokenize(expr)
	if err != nil {
		return nil, fmt.Errorf("tokenize %q: %w", expr, err)
	}

	p := &parser{tokens: tokens}
	root, err := p.parseExpr()
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", expr, err)
	}

	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("unexpected trailing tokens in %q at position %d", expr, p.pos)
	}

	return &Rule{raw: expr, root: root}, nil
}

// Eval evaluates the compiled rule against the given match config.
func (r *Rule) Eval(cfg *MatchConfig) bool {
	if r == nil || r.root == nil {
		return false
	}
	return r.root.eval(cfg)
}

// String returns the original DSL expression.
func (r *Rule) String() string {
	if r == nil {
		return ""
	}
	return r.raw
}

// EvalExpr is a convenience function that compiles and evaluates in one step.
// For repeated evaluation, use CompileRule + Rule.Eval instead.
func EvalExpr(expr string, cfg *MatchConfig) (bool, error) {
	rule, err := CompileRule(expr)
	if err != nil {
		return false, err
	}
	return rule.Eval(cfg), nil
}
