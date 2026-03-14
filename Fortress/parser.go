package main

import (
	"fmt"
	"strings"
)

// ─── AST Node Types ────────────────────────────────────────────────────────────

type Node interface {
	nodeType() string
	String() string
}

// Program is the root node
type Program struct {
	Statements []Node
}

func (p *Program) nodeType() string { return "Program" }
func (p *Program) String() string   { return "Program" }

// Literals
type IntLiteral struct {
	Value int64
	Line  int
}

func (n *IntLiteral) nodeType() string { return "IntLiteral" }
func (n *IntLiteral) String() string   { return fmt.Sprintf("%d", n.Value) }

type FloatLiteral struct {
	Value float64
	Line  int
}

func (n *FloatLiteral) nodeType() string { return "FloatLiteral" }
func (n *FloatLiteral) String() string   { return fmt.Sprintf("%f", n.Value) }

type StringLiteral struct {
	Value string
	Line  int
}

func (n *StringLiteral) nodeType() string { return "StringLiteral" }
func (n *StringLiteral) String() string   { return fmt.Sprintf("%q", n.Value) }

type BoolLiteral struct {
	Value bool
	Line  int
}

func (n *BoolLiteral) nodeType() string { return "BoolLiteral" }
func (n *BoolLiteral) String() string   { return fmt.Sprintf("%v", n.Value) }

type NullLiteral struct {
	Line int
}

func (n *NullLiteral) nodeType() string { return "NullLiteral" }
func (n *NullLiteral) String() string   { return "null" }

type ListLiteral struct {
	Elements []Node
	Line     int
}

func (n *ListLiteral) nodeType() string { return "ListLiteral" }
func (n *ListLiteral) String() string   { return "List[...]" }

type MapLiteral struct {
	Pairs []MapPair
	Line  int
}

type MapPair struct {
	Key   Node
	Value Node
}

func (n *MapLiteral) nodeType() string { return "MapLiteral" }
func (n *MapLiteral) String() string   { return "Map{...}" }

// Identifier
type Identifier struct {
	Name string
	Line int
}

func (n *Identifier) nodeType() string { return "Identifier" }
func (n *Identifier) String() string   { return n.Name }

// Let statement
type LetStatement struct {
	Name  string
	Value Node
	Line  int
}

func (n *LetStatement) nodeType() string { return "LetStatement" }
func (n *LetStatement) String() string   { return fmt.Sprintf("let %s = ...", n.Name) }

// Assignment
type AssignStatement struct {
	Target Node // Identifier or IndexExpr or MemberExpr
	Value  Node
	Op     string // "=", "+=", "-="
	Line   int
}

func (n *AssignStatement) nodeType() string { return "AssignStatement" }
func (n *AssignStatement) String() string   { return fmt.Sprintf("%s %s ...", n.Target, n.Op) }

// Increment/Decrement
type IncDecStatement struct {
	Target Node
	Op     string // "++" or "--"
	Line   int
}

func (n *IncDecStatement) nodeType() string { return "IncDecStatement" }
func (n *IncDecStatement) String() string   { return fmt.Sprintf("%s%s", n.Target, n.Op) }

// Binary expression
type BinaryExpr struct {
	Left  Node
	Op    string
	Right Node
	Line  int
}

func (n *BinaryExpr) nodeType() string { return "BinaryExpr" }
func (n *BinaryExpr) String() string   { return fmt.Sprintf("(%s %s %s)", n.Left, n.Op, n.Right) }

// Unary expression
type UnaryExpr struct {
	Op      string
	Operand Node
	Line    int
}

func (n *UnaryExpr) nodeType() string { return "UnaryExpr" }
func (n *UnaryExpr) String() string   { return fmt.Sprintf("(%s %s)", n.Op, n.Operand) }

// Concatenation: left -> right
type ConcatExpr struct {
	Left  Node
	Right Node
	Line  int
}

func (n *ConcatExpr) nodeType() string { return "ConcatExpr" }
func (n *ConcatExpr) String() string   { return fmt.Sprintf("(%s -> %s)", n.Left, n.Right) }

// Index expression: arr[i]
type IndexExpr struct {
	Object Node
	Index  Node
	Line   int
}

func (n *IndexExpr) nodeType() string { return "IndexExpr" }
func (n *IndexExpr) String() string   { return fmt.Sprintf("%s[%s]", n.Object, n.Index) }

// Member expression: obj.field
type MemberExpr struct {
	Object Node
	Field  string
	Line   int
}

func (n *MemberExpr) nodeType() string { return "MemberExpr" }
func (n *MemberExpr) String() string   { return fmt.Sprintf("%s.%s", n.Object, n.Field) }

// Function call
type CallExpr struct {
	Callee Node
	Args   []Node
	Line   int
}

func (n *CallExpr) nodeType() string { return "CallExpr" }
func (n *CallExpr) String() string   { return fmt.Sprintf("%s(...)", n.Callee) }

// Probe (function definition)
type ProbeStatement struct {
	Name   string
	Params []string
	Body   []Node
	Line   int
}

func (n *ProbeStatement) nodeType() string { return "ProbeStatement" }
func (n *ProbeStatement) String() string   { return fmt.Sprintf("probe %s(...)", n.Name) }

// Return
type ReturnStatement struct {
	Value Node
	Line  int
}

func (n *ReturnStatement) nodeType() string { return "ReturnStatement" }
func (n *ReturnStatement) String() string   { return "return ..." }

// Compute (print)
type ComputeStatement struct {
	Args []Node
	Line int
}

func (n *ComputeStatement) nodeType() string { return "ComputeStatement" }
func (n *ComputeStatement) String() string   { return "compute(...)" }

// Capture (input)
type CaptureStatement struct {
	Prompt Node
	Target string
	Line   int
}

func (n *CaptureStatement) nodeType() string { return "CaptureStatement" }
func (n *CaptureStatement) String() string   { return fmt.Sprintf("capture -> %s", n.Target) }

// If / elif / else
type IfStatement struct {
	Condition Node
	Body      []Node
	ElseIfs   []ElseIf
	ElseBody  []Node
	Line      int
}

type ElseIf struct {
	Condition Node
	Body      []Node
}

func (n *IfStatement) nodeType() string { return "IfStatement" }
func (n *IfStatement) String() string   { return "if ..." }

// Scan (C-style for loop): scan (init; condition; post) { }
type ScanStatement struct {
	Init      Node
	Condition Node
	Post      Node
	Body      []Node
	Line      int
}

func (n *ScanStatement) nodeType() string { return "ScanStatement" }
func (n *ScanStatement) String() string   { return "scan (...)" }

// Each (for-each): each item in collection { }
type EachStatement struct {
	Var        string
	Collection Node
	Body       []Node
	Line       int
}

func (n *EachStatement) nodeType() string { return "EachStatement" }
func (n *EachStatement) String() string   { return fmt.Sprintf("each %s in ...", n.Var) }

// Until (while loop): until condition { }
type UntilStatement struct {
	Condition Node
	Body      []Node
	Line      int
}

func (n *UntilStatement) nodeType() string { return "UntilStatement" }
func (n *UntilStatement) String() string   { return "until ..." }

// Break / Continue
type BreakStatement struct{ Line int }

func (n *BreakStatement) nodeType() string { return "BreakStatement" }
func (n *BreakStatement) String() string   { return "break" }

type ContinueStatement struct{ Line int }

func (n *ContinueStatement) nodeType() string { return "ContinueStatement" }
func (n *ContinueStatement) String() string   { return "continue" }

// Import statement
type ImportStatement struct {
	Module string
	Alias  string
	Line   int
}

func (n *ImportStatement) nodeType() string { return "ImportStatement" }
func (n *ImportStatement) String() string   { return fmt.Sprintf("import %s", n.Module) }

// Network/OSINT builtin call nodes
type BuiltinCall struct {
	Name string
	Args []Node
	Line int
}

func (n *BuiltinCall) nodeType() string { return "BuiltinCall" }
func (n *BuiltinCall) String() string   { return fmt.Sprintf("%s(...)", n.Name) }

// Report statement
type ReportStatement struct {
	Title  Node
	Fields []ReportField
	Format Node // "json", "text", "html"
	Line   int
}

type ReportField struct {
	Label string
	Value Node
}

func (n *ReportStatement) nodeType() string { return "ReportStatement" }
func (n *ReportStatement) String() string   { return "report {...}" }

// Save statement: save data to "file.txt"
type SaveStatement struct {
	Data     Node
	Filename Node
	Line     int
}

func (n *SaveStatement) nodeType() string { return "SaveStatement" }
func (n *SaveStatement) String() string   { return "save ... to ..." }

// Expression statement (standalone call)
type ExprStatement struct {
	Expr Node
	Line int
}

func (n *ExprStatement) nodeType() string { return "ExprStatement" }
func (n *ExprStatement) String() string   { return n.Expr.String() }

// ─── Parser ────────────────────────────────────────────────────────────────────

type Parser struct {
	tokens []Token
	pos    int
}

func NewParser(tokens []Token) *Parser {
	// Filter newlines for statement separation (handle them explicitly)
	return &Parser{tokens: tokens, pos: 0}
}

func (p *Parser) peek() Token {
	for p.pos < len(p.tokens) {
		t := p.tokens[p.pos]
		if t.Type == TOKEN_NEWLINE || t.Type == TOKEN_SEMI {
			p.pos++
			continue
		}
		return t
	}
	return Token{Type: TOKEN_EOF}
}

func (p *Parser) peekRaw() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TOKEN_EOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) advance() Token {
	// Skip newlines/semis
	for p.pos < len(p.tokens) {
		t := p.tokens[p.pos]
		p.pos++
		if t.Type == TOKEN_NEWLINE || t.Type == TOKEN_SEMI {
			continue
		}
		return t
	}
	return Token{Type: TOKEN_EOF}
}

func (p *Parser) advanceRaw() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TOKEN_EOF}
	}
	t := p.tokens[p.pos]
	p.pos++
	return t
}

func (p *Parser) expect(tt TokenType) (Token, error) {
	t := p.advance()
	if t.Type != tt {
		return t, fmt.Errorf("line %d: expected %s, got %s (%q)", t.Line, tt, t.Type, t.Literal)
	}
	return t, nil
}

// expectName accepts any token as an identifier name.
// This allows keywords like 'scan', 'port', 'resolve', 'each', etc.
// to be used as variable names, parameter names, field labels, etc.
func (p *Parser) expectName() (Token, error) {
	t := p.advance()
	if t.Type == TOKEN_EOF {
		return t, fmt.Errorf("line %d: expected identifier, got EOF", t.Line)
	}
	if t.Type == TOKEN_NEWLINE || t.Type == TOKEN_SEMI {
		return t, fmt.Errorf("line %d: expected identifier, got newline", t.Line)
	}
	if t.Type == TOKEN_LBRACE || t.Type == TOKEN_RBRACE ||
		t.Type == TOKEN_LPAREN || t.Type == TOKEN_RPAREN ||
		t.Type == TOKEN_LBRACKET || t.Type == TOKEN_RBRACKET ||
		t.Type == TOKEN_COMMA || t.Type == TOKEN_COLON ||
		t.Type == TOKEN_ASSIGN || t.Type == TOKEN_ARROW {
		return t, fmt.Errorf("line %d: expected identifier, got %s (%q)", t.Line, t.Type, t.Literal)
	}
	// All keywords and identifiers are valid as names in name-position
	return t, nil
}

func (p *Parser) skipNewlines() {
	for p.pos < len(p.tokens) {
		t := p.tokens[p.pos]
		if t.Type == TOKEN_NEWLINE || t.Type == TOKEN_SEMI {
			p.pos++
		} else {
			break
		}
	}
}

func (p *Parser) Parse() (*Program, error) {
	prog := &Program{}
	p.skipNewlines()
	for p.peek().Type != TOKEN_EOF {
		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		if stmt != nil {
			prog.Statements = append(prog.Statements, stmt)
		}
		p.skipNewlines()
	}
	return prog, nil
}

func (p *Parser) parseBlock() ([]Node, error) {
	_, err := p.expect(TOKEN_LBRACE)
	if err != nil {
		return nil, err
	}
	p.skipNewlines()
	var stmts []Node
	for p.peek().Type != TOKEN_RBRACE && p.peek().Type != TOKEN_EOF {
		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
		p.skipNewlines()
	}
	_, err = p.expect(TOKEN_RBRACE)
	if err != nil {
		return nil, err
	}
	return stmts, nil
}

func (p *Parser) parseStatement() (Node, error) {
	t := p.peek()
	switch t.Type {
	case TOKEN_PROBE:
		return p.parseProbe()
	case TOKEN_LET:
		return p.parseLet()
	case TOKEN_IF:
		return p.parseIf()
	case TOKEN_SCAN:
		// 'scan' is a for-loop keyword ONLY when followed by '('
		// Otherwise treat it as an identifier (variable named 'scan')
		if p.peekSecond().Type == TOKEN_LPAREN {
			return p.parseScan()
		}
		return p.parseIdentStatement()
	case TOKEN_EACH:
		// 'each' is a for-each ONLY when followed by an identifier then 'in'
		// Otherwise treat as identifier
		if p.isEachLoop() {
			return p.parseEach()
		}
		return p.parseIdentStatement()
	case TOKEN_UNTIL:
		return p.parseUntil()
	case TOKEN_RETURN:
		return p.parseReturn()
	case TOKEN_BREAK:
		p.advance()
		return &BreakStatement{Line: t.Line}, nil
	case TOKEN_CONTINUE:
		p.advance()
		return &ContinueStatement{Line: t.Line}, nil
	case TOKEN_COMPUTE:
		return p.parseCompute()
	case TOKEN_CAPTURE:
		return p.parseCapture()
	case TOKEN_IMPORT:
		return p.parseImport()
	case TOKEN_REPORT:
		return p.parseReport()
	case TOKEN_SAVE:
		return p.parseSave()
	// Network builtins as statements — only when followed by '('
	case TOKEN_RESOLVE, TOKEN_TRACE, TOKEN_GEOLOCATE, TOKEN_WHOIS,
		TOKEN_PORTSCAN, TOKEN_PHONINFO, TOKEN_HEADERS, TOKEN_CRAWL,
		TOKEN_SUBNET, TOKEN_REVDNS, TOKEN_BANNER, TOKEN_CERTINFO,
		TOKEN_ASNLOOKUP, TOKEN_EMAILVAL, TOKEN_MACVENDOR, TOKEN_IPRANGE,
		TOKEN_DNSBRUTE, TOKEN_SSLGRADE, TOKEN_PASTEFIND,
		TOKEN_HTTPFUZZ, TOKEN_TLSCHAIN:
		if p.peekSecond().Type == TOKEN_LPAREN {
			expr, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			return &ExprStatement{Expr: expr, Line: t.Line}, nil
		}
		// Used as variable name
		return p.parseIdentStatement()
	case TOKEN_IDENT:
		return p.parseIdentStatement()
	case TOKEN_EOF:
		return nil, nil
	default:
		expr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &ExprStatement{Expr: expr, Line: t.Line}, nil
	}
}

// peekSecond returns the second non-newline token without consuming anything.
func (p *Parser) peekSecond() Token {
	saved := p.pos
	p.advance() // skip first
	t := p.peek()
	p.pos = saved
	return t
}

// isEachLoop checks if current 'each' is a for-each loop (each <name> in ...)
// vs being used as an identifier.
func (p *Parser) isEachLoop() bool {
	saved := p.pos
	defer func() { p.pos = saved }()
	p.advance() // consume 'each'
	// next should be any name token
	name := p.peek()
	if name.Type == TOKEN_EOF || name.Type == TOKEN_NEWLINE {
		return false
	}
	p.advance() // consume name
	// next should be 'in'
	return p.peek().Type == TOKEN_IN
}

func (p *Parser) parseProbe() (*ProbeStatement, error) {
	tok := p.advance() // consume 'probe'
	nameTok, err := p.expectName()
	if err != nil {
		return nil, err
	}
	_, err = p.expect(TOKEN_LPAREN)
	if err != nil {
		return nil, err
	}
	var params []string
	for p.peek().Type != TOKEN_RPAREN && p.peek().Type != TOKEN_EOF {
		pt, err := p.expectName()
		if err != nil {
			return nil, err
		}
		params = append(params, pt.Literal)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	_, err = p.expect(TOKEN_RPAREN)
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &ProbeStatement{Name: nameTok.Literal, Params: params, Body: body, Line: tok.Line}, nil
}

func (p *Parser) parseLet() (*LetStatement, error) {
	tok := p.advance() // consume 'let'
	nameTok, err := p.expectName()
	if err != nil {
		return nil, err
	}
	_, err = p.expect(TOKEN_ASSIGN)
	if err != nil {
		return nil, err
	}
	val, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	return &LetStatement{Name: nameTok.Literal, Value: val, Line: tok.Line}, nil
}

func (p *Parser) parseIf() (*IfStatement, error) {
	tok := p.advance() // consume 'if'
	cond, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	node := &IfStatement{Condition: cond, Body: body, Line: tok.Line}

	for p.peek().Type == TOKEN_ELIF {
		p.advance()
		ec, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		eb, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		node.ElseIfs = append(node.ElseIfs, ElseIf{Condition: ec, Body: eb})
	}
	if p.peek().Type == TOKEN_ELSE {
		p.advance()
		eb, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		node.ElseBody = eb
	}
	return node, nil
}

func (p *Parser) parseScan() (*ScanStatement, error) {
	tok := p.advance() // consume 'scan'
	_, err := p.expect(TOKEN_LPAREN)
	if err != nil {
		return nil, err
	}

	// init
	var init Node
	if p.peek().Type != TOKEN_SEMI {
		init, err = p.parseSimpleStatement()
		if err != nil {
			return nil, err
		}
	}
	// consume ;
	if p.peek().Type == TOKEN_SEMI {
		p.advance()
	}

	// condition
	var cond Node
	if p.peek().Type != TOKEN_SEMI {
		cond, err = p.parseExpr()
		if err != nil {
			return nil, err
		}
	}
	if p.peek().Type == TOKEN_SEMI {
		p.advance()
	}

	// post
	var post Node
	if p.peek().Type != TOKEN_RPAREN {
		post, err = p.parseSimpleStatement()
		if err != nil {
			return nil, err
		}
	}
	_, err = p.expect(TOKEN_RPAREN)
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &ScanStatement{Init: init, Condition: cond, Post: post, Body: body, Line: tok.Line}, nil
}

func (p *Parser) parseSimpleStatement() (Node, error) {
	t := p.peek()
	if t.Type == TOKEN_LET {
		return p.parseLet()
	}
	expr, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	// Check for assignment or inc/dec
	next := p.peek()
	if next.Type == TOKEN_ASSIGN || next.Type == TOKEN_PLUSEQ || next.Type == TOKEN_MINUSEQ {
		op := p.advance().Literal
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStatement{Target: expr, Value: val, Op: op, Line: t.Line}, nil
	}
	if next.Type == TOKEN_INCREMENT {
		p.advance()
		return &IncDecStatement{Target: expr, Op: "++", Line: t.Line}, nil
	}
	if next.Type == TOKEN_DECREMENT {
		p.advance()
		return &IncDecStatement{Target: expr, Op: "--", Line: t.Line}, nil
	}
	return &ExprStatement{Expr: expr, Line: t.Line}, nil
}

func (p *Parser) parseEach() (*EachStatement, error) {
	tok := p.advance() // consume 'each'
	varTok, err := p.expectName()
	if err != nil {
		return nil, err
	}
	_, err = p.expect(TOKEN_IN)
	if err != nil {
		return nil, err
	}
	coll, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &EachStatement{Var: varTok.Literal, Collection: coll, Body: body, Line: tok.Line}, nil
}

func (p *Parser) parseUntil() (*UntilStatement, error) {
	tok := p.advance() // consume 'until'
	cond, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &UntilStatement{Condition: cond, Body: body, Line: tok.Line}, nil
}

func (p *Parser) parseReturn() (*ReturnStatement, error) {
	tok := p.advance()
	// Optional value
	var val Node
	next := p.peek()
	if next.Type != TOKEN_NEWLINE && next.Type != TOKEN_RBRACE && next.Type != TOKEN_EOF && next.Type != TOKEN_SEMI {
		val, _ = p.parseExpr()
	}
	return &ReturnStatement{Value: val, Line: tok.Line}, nil
}

func (p *Parser) parseCompute() (*ComputeStatement, error) {
	tok := p.advance()
	_, err := p.expect(TOKEN_LPAREN)
	if err != nil {
		return nil, err
	}
	var args []Node
	for p.peek().Type != TOKEN_RPAREN && p.peek().Type != TOKEN_EOF {
		arg, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	_, err = p.expect(TOKEN_RPAREN)
	if err != nil {
		return nil, err
	}
	return &ComputeStatement{Args: args, Line: tok.Line}, nil
}

func (p *Parser) parseCapture() (*CaptureStatement, error) {
	tok := p.advance()
	_, err := p.expect(TOKEN_LPAREN)
	if err != nil {
		return nil, err
	}
	prompt, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	_, err = p.expect(TOKEN_RPAREN)
	if err != nil {
		return nil, err
	}
	_, err = p.expect(TOKEN_ARROW)
	if err != nil {
		return nil, err
	}
	targetTok, err := p.expectName()
	if err != nil {
		return nil, err
	}
	return &CaptureStatement{Prompt: prompt, Target: targetTok.Literal, Line: tok.Line}, nil
}

func (p *Parser) parseImport() (*ImportStatement, error) {
	tok := p.advance()
	modTok, err := p.expectName()
	if err != nil {
		return nil, err
	}
	alias := modTok.Literal
	if p.peek().Type == TOKEN_AS {
		p.advance()
		aliasTok, err := p.expectName()
		if err != nil {
			return nil, err
		}
		alias = aliasTok.Literal
	}
	return &ImportStatement{Module: modTok.Literal, Alias: alias, Line: tok.Line}, nil
}

func (p *Parser) parseReport() (*ReportStatement, error) {
	tok := p.advance()
	title, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	// Optional format: report "title" as "json" { }
	var format Node
	if p.peek().Type == TOKEN_AS {
		p.advance()
		format, err = p.parseExpr()
		if err != nil {
			return nil, err
		}
	}
	_, err = p.expect(TOKEN_LBRACE)
	if err != nil {
		return nil, err
	}
	p.skipNewlines()
	var fields []ReportField
	for p.peek().Type != TOKEN_RBRACE && p.peek().Type != TOKEN_EOF {
		labelTok, err := p.expectName()
		if err != nil {
			return nil, err
		}
		_, err = p.expect(TOKEN_COLON)
		if err != nil {
			return nil, err
		}
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		fields = append(fields, ReportField{Label: labelTok.Literal, Value: val})
		// Consume optional trailing comma
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
		p.skipNewlines()
	}
	_, err = p.expect(TOKEN_RBRACE)
	if err != nil {
		return nil, err
	}
	return &ReportStatement{Title: title, Fields: fields, Format: format, Line: tok.Line}, nil
}

func (p *Parser) parseSave() (*SaveStatement, error) {
	tok := p.advance()
	data, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	// expect 'to' (ident)
	toTok := p.advance()
	if toTok.Literal != "to" {
		return nil, fmt.Errorf("line %d: expected 'to' after save expression", tok.Line)
	}
	filename, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	return &SaveStatement{Data: data, Filename: filename, Line: tok.Line}, nil
}

func (p *Parser) parseIdentStatement() (Node, error) {
	t := p.peek()
	expr, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	next := p.peek()
	if next.Type == TOKEN_ASSIGN || next.Type == TOKEN_PLUSEQ || next.Type == TOKEN_MINUSEQ {
		op := p.advance().Literal
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStatement{Target: expr, Value: val, Op: op, Line: t.Line}, nil
	}
	if next.Type == TOKEN_INCREMENT {
		p.advance()
		return &IncDecStatement{Target: expr, Op: "++", Line: t.Line}, nil
	}
	if next.Type == TOKEN_DECREMENT {
		p.advance()
		return &IncDecStatement{Target: expr, Op: "--", Line: t.Line}, nil
	}
	return &ExprStatement{Expr: expr, Line: t.Line}, nil
}

// ─── Expression Parsing (Pratt-style) ─────────────────────────────────────────

func (p *Parser) parseExpr() (Node, error) {
	return p.parseOr()
}

func (p *Parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_OR {
		op := p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Op: "or", Right: right, Line: op.Line}
	}
	return left, nil
}

func (p *Parser) parseAnd() (Node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_AND {
		op := p.advance()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Op: "and", Right: right, Line: op.Line}
	}
	return left, nil
}

func (p *Parser) parseNot() (Node, error) {
	if p.peek().Type == TOKEN_NOT {
		op := p.advance()
		operand, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		return &UnaryExpr{Op: "not", Operand: operand, Line: op.Line}, nil
	}
	return p.parseComparison()
}

func (p *Parser) parseComparison() (Node, error) {
	left, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		var op string
		switch t.Type {
		case TOKEN_EQ:
			op = "=="
		case TOKEN_NEQ:
			op = "!="
		case TOKEN_LT:
			op = "<"
		case TOKEN_LTE:
			op = "<="
		case TOKEN_GT:
			op = ">"
		case TOKEN_GTE:
			op = ">="
		default:
			return left, nil
		}
		line := p.advance().Line
		right, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Op: op, Right: right, Line: line}
	}
}

func (p *Parser) parseConcat() (Node, error) {
	left, err := p.parseAddSub()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_ARROW {
		line := p.advance().Line
		right, err := p.parseAddSub()
		if err != nil {
			return nil, err
		}
		left = &ConcatExpr{Left: left, Right: right, Line: line}
	}
	return left, nil
}

func (p *Parser) parseAddSub() (Node, error) {
	left, err := p.parseMulDiv()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_PLUS || p.peek().Type == TOKEN_MINUS {
		t := p.advance()
		right, err := p.parseMulDiv()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Op: t.Literal, Right: right, Line: t.Line}
	}
	return left, nil
}

func (p *Parser) parseMulDiv() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_STAR || p.peek().Type == TOKEN_SLASH || p.peek().Type == TOKEN_PERCENT {
		t := p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Op: t.Literal, Right: right, Line: t.Line}
	}
	return left, nil
}

func (p *Parser) parseUnary() (Node, error) {
	t := p.peek()
	if t.Type == TOKEN_MINUS {
		p.advance()
		operand, err := p.parsePostfix()
		if err != nil {
			return nil, err
		}
		return &UnaryExpr{Op: "-", Operand: operand, Line: t.Line}, nil
	}
	return p.parsePostfix()
}

func (p *Parser) parsePostfix() (Node, error) {
	node, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.Type == TOKEN_DOT {
			p.advance()
			// Field names can be any token (including keywords like 'scan', 'port', etc.)
			fieldTok, err := p.expectName()
			if err != nil {
				return nil, err
			}
			// Could be a method call
			if p.peek().Type == TOKEN_LPAREN {
				p.advance()
				args, err := p.parseArgList()
				if err != nil {
					return nil, err
				}
				callee := &MemberExpr{Object: node, Field: fieldTok.Literal, Line: fieldTok.Line}
				node = &CallExpr{Callee: callee, Args: args, Line: fieldTok.Line}
			} else {
				node = &MemberExpr{Object: node, Field: fieldTok.Literal, Line: fieldTok.Line}
			}
		} else if t.Type == TOKEN_LBRACKET {
			p.advance()
			idx, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			_, err = p.expect(TOKEN_RBRACKET)
			if err != nil {
				return nil, err
			}
			node = &IndexExpr{Object: node, Index: idx, Line: t.Line}
		} else if t.Type == TOKEN_LPAREN {
			p.advance()
			args, err := p.parseArgList()
			if err != nil {
				return nil, err
			}
			node = &CallExpr{Callee: node, Args: args, Line: t.Line}
		} else {
			break
		}
	}
	return node, nil
}

func (p *Parser) parseArgList() ([]Node, error) {
	var args []Node
	for p.peek().Type != TOKEN_RPAREN && p.peek().Type != TOKEN_EOF {
		arg, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	_, err := p.expect(TOKEN_RPAREN)
	if err != nil {
		return nil, err
	}
	return args, nil
}

func (p *Parser) parsePrimary() (Node, error) {
	t := p.peek()

	switch t.Type {
	case TOKEN_INT:
		p.advance()
		var v int64
		fmt.Sscanf(t.Literal, "%d", &v)
		return &IntLiteral{Value: v, Line: t.Line}, nil

	case TOKEN_FLOAT:
		p.advance()
		var v float64
		fmt.Sscanf(t.Literal, "%f", &v)
		return &FloatLiteral{Value: v, Line: t.Line}, nil

	case TOKEN_STRING:
		p.advance()
		return &StringLiteral{Value: t.Literal, Line: t.Line}, nil

	case TOKEN_TRUE:
		p.advance()
		return &BoolLiteral{Value: true, Line: t.Line}, nil

	case TOKEN_FALSE:
		p.advance()
		return &BoolLiteral{Value: false, Line: t.Line}, nil

	case TOKEN_NULL_KW:
		p.advance()
		return &NullLiteral{Line: t.Line}, nil

	case TOKEN_LBRACKET:
		return p.parseListLiteral()

	case TOKEN_LBRACE:
		return p.parseMapLiteral()

	case TOKEN_LPAREN:
		p.advance()
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		_, err = p.expect(TOKEN_RPAREN)
		if err != nil {
			return nil, err
		}
		return inner, nil

	// Network/OSINT builtins — only treat as builtin call when followed by '('
	case TOKEN_RESOLVE, TOKEN_TRACE, TOKEN_GEOLOCATE, TOKEN_WHOIS,
		TOKEN_PORTSCAN, TOKEN_PHONINFO, TOKEN_HEADERS, TOKEN_CRAWL,
		TOKEN_SUBNET, TOKEN_REVDNS, TOKEN_BANNER, TOKEN_CERTINFO,
		TOKEN_ASNLOOKUP, TOKEN_EMAILVAL, TOKEN_MACVENDOR, TOKEN_IPRANGE,
		TOKEN_DNSBRUTE, TOKEN_SSLGRADE, TOKEN_PASTEFIND,
		TOKEN_HTTPFUZZ, TOKEN_TLSCHAIN:
		// Peek ahead: if next is '(', it's a builtin call; otherwise treat as identifier
		savedPos := p.pos
		name := p.advance().Literal
		if p.peek().Type == TOKEN_LPAREN {
			p.advance()
			args, err := p.parseArgList()
			if err != nil {
				return nil, err
			}
			return &BuiltinCall{Name: name, Args: args, Line: t.Line}, nil
		}
		// Used as identifier (e.g. variable named 'scan' or 'port')
		p.pos = savedPos
		return &Identifier{Name: name, Line: t.Line}, nil

	case TOKEN_IDENT:
		p.advance()
		return &Identifier{Name: t.Literal, Line: t.Line}, nil

	default:
		// Any other keyword used in expression position — treat as identifier
		// This handles: let scan = ..., each port in ..., etc. when the
		// keyword-named variable appears on the right-hand side of an expression
		if isKeywordToken(t.Type) {
			p.advance()
			return &Identifier{Name: t.Literal, Line: t.Line}, nil
		}
		return nil, fmt.Errorf("line %d: unexpected token %s (%q)", t.Line, t.Type, t.Literal)
	}
}

func (p *Parser) parseListLiteral() (*ListLiteral, error) {
	t := p.advance() // consume '['
	var elems []Node
	for p.peek().Type != TOKEN_RBRACKET && p.peek().Type != TOKEN_EOF {
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		elems = append(elems, e)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	_, err := p.expect(TOKEN_RBRACKET)
	if err != nil {
		return nil, err
	}
	return &ListLiteral{Elements: elems, Line: t.Line}, nil
}

func (p *Parser) parseMapLiteral() (*MapLiteral, error) {
	t := p.advance() // consume '{'
	p.skipNewlines()
	var pairs []MapPair
	for p.peek().Type != TOKEN_RBRACE && p.peek().Type != TOKEN_EOF {
		key, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		_, err = p.expect(TOKEN_COLON)
		if err != nil {
			return nil, err
		}
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, MapPair{Key: key, Value: val})
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
		p.skipNewlines()
	}
	_, err := p.expect(TOKEN_RBRACE)
	if err != nil {
		return nil, err
	}
	return &MapLiteral{Pairs: pairs, Line: t.Line}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func joinNodes(nodes []Node) string {
	parts := make([]string, len(nodes))
	for i, n := range nodes {
		parts[i] = n.String()
	}
	return strings.Join(parts, ", ")
}

// isKeywordToken returns true for tokens that are keywords but can legally
// appear as identifier names in expression/name position.
func isKeywordToken(tt TokenType) bool {
	switch tt {
	case TOKEN_PROBE, TOKEN_SCAN, TOKEN_EACH, TOKEN_IN, TOKEN_UNTIL,
		TOKEN_IF, TOKEN_ELIF, TOKEN_ELSE, TOKEN_RETURN, TOKEN_BREAK,
		TOKEN_CONTINUE, TOKEN_COMPUTE, TOKEN_CAPTURE, TOKEN_LET,
		TOKEN_IMPORT, TOKEN_FROM, TOKEN_AS,
		TOKEN_RESOLVE, TOKEN_TRACE, TOKEN_GEOLOCATE, TOKEN_WHOIS,
		TOKEN_PORTSCAN, TOKEN_PHONINFO, TOKEN_HEADERS, TOKEN_CRAWL,
		TOKEN_SUBNET, TOKEN_REVDNS, TOKEN_BANNER, TOKEN_CERTINFO,
		TOKEN_ASNLOOKUP, TOKEN_EMAILVAL, TOKEN_MACVENDOR, TOKEN_IPRANGE,
		TOKEN_DNSBRUTE, TOKEN_SSLGRADE, TOKEN_PASTEFIND,
		TOKEN_HTTPFUZZ, TOKEN_TLSCHAIN,
		TOKEN_REPORT, TOKEN_SAVE,
		TOKEN_AND, TOKEN_OR, TOKEN_NOT:
		return true
	}
	return false
}
