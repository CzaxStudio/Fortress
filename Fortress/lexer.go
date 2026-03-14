package main

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType represents all token types in the Fortress language
type TokenType string

const (
	// Literals
	TOKEN_INT    TokenType = "INT"
	TOKEN_FLOAT  TokenType = "FLOAT"
	TOKEN_STRING TokenType = "STRING"
	TOKEN_BOOL   TokenType = "BOOL"
	TOKEN_NULL   TokenType = "NULL"
	TOKEN_IDENT  TokenType = "IDENT"

	// Keywords
	TOKEN_PROBE    TokenType = "probe" // function definition
	TOKEN_SCAN     TokenType = "scan"  // loop
	TOKEN_EACH     TokenType = "each"  // for-each
	TOKEN_IN       TokenType = "in"    // in (for each)
	TOKEN_UNTIL    TokenType = "until" // while loop
	TOKEN_IF       TokenType = "if"
	TOKEN_ELIF     TokenType = "elif"
	TOKEN_ELSE     TokenType = "else"
	TOKEN_RETURN   TokenType = "return"
	TOKEN_BREAK    TokenType = "break"
	TOKEN_CONTINUE TokenType = "continue"
	TOKEN_COMPUTE  TokenType = "compute" // print
	TOKEN_CAPTURE  TokenType = "capture" // input
	TOKEN_LET      TokenType = "let"     // variable declaration
	TOKEN_IMPORT   TokenType = "import"
	TOKEN_TRUE     TokenType = "true"
	TOKEN_FALSE    TokenType = "false"
	TOKEN_NULL_KW  TokenType = "null"
	TOKEN_AND      TokenType = "and"
	TOKEN_OR       TokenType = "or"
	TOKEN_NOT      TokenType = "not"
	TOKEN_FROM     TokenType = "from"
	TOKEN_AS       TokenType = "as"

	// Network/OSINT builtins (keywords)
	TOKEN_RESOLVE   TokenType = "resolve"   // DNS resolve
	TOKEN_TRACE     TokenType = "trace"     // traceroute
	TOKEN_GEOLOCATE TokenType = "geolocate" // IP geolocation
	TOKEN_WHOIS     TokenType = "whois"     // WHOIS lookup
	TOKEN_PORTSCAN  TokenType = "portscan"  // port scan
	TOKEN_PHONINFO  TokenType = "phoninfo"  // phone number info
	TOKEN_HEADERS   TokenType = "headers"   // HTTP headers
	TOKEN_CRAWL     TokenType = "crawl"     // web crawl metadata
	TOKEN_SUBNET    TokenType = "subnet"    // subnet info
	TOKEN_REVDNS    TokenType = "revdns"    // reverse DNS
	TOKEN_BANNER    TokenType = "banner"    // banner grabbing
	TOKEN_CERTINFO  TokenType = "certinfo"  // TLS cert info
	TOKEN_ASNLOOKUP TokenType = "asnlookup" // ASN lookup
	TOKEN_EMAILVAL  TokenType = "emailval"  // email validation/info
	TOKEN_MACVENDOR TokenType = "macvendor" // MAC vendor lookup
	TOKEN_IPRANGE   TokenType = "iprange"   // IP range expansion
	TOKEN_DNSBRUTE  TokenType = "dnsbrute"  // subdomain enumeration
	TOKEN_SSLGRADE  TokenType = "sslgrade"  // SSL/TLS grade assessment
	TOKEN_PASTEFIND TokenType = "pastefind" // paste/leak site search
	TOKEN_HTTPFUZZ  TokenType = "httpfuzz"  // HTTP path fuzzer
	TOKEN_TLSCHAIN  TokenType = "tlschain"  // TLS chain tracer
	TOKEN_REPORT    TokenType = "report"    // generate report
	TOKEN_SAVE      TokenType = "save"      // save to file

	// Operators
	TOKEN_ASSIGN    TokenType = "="
	TOKEN_PLUS      TokenType = "+"
	TOKEN_MINUS     TokenType = "-"
	TOKEN_STAR      TokenType = "*"
	TOKEN_SLASH     TokenType = "/"
	TOKEN_PERCENT   TokenType = "%"
	TOKEN_EQ        TokenType = "=="
	TOKEN_NEQ       TokenType = "!="
	TOKEN_LT        TokenType = "<"
	TOKEN_LTE       TokenType = "<="
	TOKEN_GT        TokenType = ">"
	TOKEN_GTE       TokenType = ">="
	TOKEN_ARROW     TokenType = "->" // concatenation operator
	TOKEN_PLUSEQ    TokenType = "+="
	TOKEN_MINUSEQ   TokenType = "-="
	TOKEN_INCREMENT TokenType = "++"
	TOKEN_DECREMENT TokenType = "--"

	// Delimiters
	TOKEN_LPAREN   TokenType = "("
	TOKEN_RPAREN   TokenType = ")"
	TOKEN_LBRACE   TokenType = "{"
	TOKEN_RBRACE   TokenType = "}"
	TOKEN_LBRACKET TokenType = "["
	TOKEN_RBRACKET TokenType = "]"
	TOKEN_COMMA    TokenType = ","
	TOKEN_DOT      TokenType = "."
	TOKEN_COLON    TokenType = ":"
	TOKEN_SEMI     TokenType = ";"
	TOKEN_NEWLINE  TokenType = "NEWLINE"

	// Special
	TOKEN_EOF     TokenType = "EOF"
	TOKEN_COMMENT TokenType = "COMMENT"
	TOKEN_HASH    TokenType = "#"
)

var keywords = map[string]TokenType{
	"probe":    TOKEN_PROBE,
	"scan":     TOKEN_SCAN,
	"each":     TOKEN_EACH,
	"in":       TOKEN_IN,
	"until":    TOKEN_UNTIL,
	"if":       TOKEN_IF,
	"elif":     TOKEN_ELIF,
	"else":     TOKEN_ELSE,
	"return":   TOKEN_RETURN,
	"break":    TOKEN_BREAK,
	"continue": TOKEN_CONTINUE,
	"compute":  TOKEN_COMPUTE,
	"capture":  TOKEN_CAPTURE,
	"let":      TOKEN_LET,
	"import":   TOKEN_IMPORT,
	"true":     TOKEN_TRUE,
	"false":    TOKEN_FALSE,
	"null":     TOKEN_NULL_KW,
	"and":      TOKEN_AND,
	"or":       TOKEN_OR,
	"not":      TOKEN_NOT,
	"from":     TOKEN_FROM,
	"as":       TOKEN_AS,
	// Network/OSINT builtins
	"resolve":   TOKEN_RESOLVE,
	"trace":     TOKEN_TRACE,
	"geolocate": TOKEN_GEOLOCATE,
	"whois":     TOKEN_WHOIS,
	"portscan":  TOKEN_PORTSCAN,
	"phoninfo":  TOKEN_PHONINFO,
	"headers":   TOKEN_HEADERS,
	"crawl":     TOKEN_CRAWL,
	"subnet":    TOKEN_SUBNET,
	"revdns":    TOKEN_REVDNS,
	"banner":    TOKEN_BANNER,
	"certinfo":  TOKEN_CERTINFO,
	"asnlookup": TOKEN_ASNLOOKUP,
	"emailval":  TOKEN_EMAILVAL,
	"macvendor": TOKEN_MACVENDOR,
	"iprange":   TOKEN_IPRANGE,
	"dnsbrute":  TOKEN_DNSBRUTE,
	"sslgrade":  TOKEN_SSLGRADE,
	"pastefind": TOKEN_PASTEFIND,
	"httpfuzz":  TOKEN_HTTPFUZZ,
	"tlschain":  TOKEN_TLSCHAIN,
	"report":    TOKEN_REPORT,
	"save":      TOKEN_SAVE,
}

// Token holds a single lexical token
type Token struct {
	Type    TokenType
	Literal string
	Line    int
	Col     int
}

func (t Token) String() string {
	return fmt.Sprintf("Token(%s, %q, L%d:C%d)", t.Type, t.Literal, t.Line, t.Col)
}

// Lexer tokenizes Fortress source code
type Lexer struct {
	source []rune
	pos    int
	line   int
	col    int
	tokens []Token
}

func NewLexer(source string) *Lexer {
	return &Lexer{
		source: []rune(source),
		pos:    0,
		line:   1,
		col:    1,
	}
}

func (l *Lexer) peek() rune {
	if l.pos >= len(l.source) {
		return 0
	}
	return l.source[l.pos]
}

func (l *Lexer) peekAt(offset int) rune {
	idx := l.pos + offset
	if idx >= len(l.source) {
		return 0
	}
	return l.source[idx]
}

func (l *Lexer) advance() rune {
	ch := l.source[l.pos]
	l.pos++
	if ch == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return ch
}

func (l *Lexer) addToken(t TokenType, lit string, line, col int) {
	l.tokens = append(l.tokens, Token{Type: t, Literal: lit, Line: line, Col: col})
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.source) {
		ch := l.peek()
		if ch == ' ' || ch == '\t' || ch == '\r' {
			l.advance()
		} else {
			break
		}
	}
}

func (l *Lexer) readString(quote rune) (string, error) {
	var sb strings.Builder
	for l.pos < len(l.source) {
		ch := l.advance()
		if ch == '\\' {
			if l.pos >= len(l.source) {
				return "", fmt.Errorf("unterminated string escape")
			}
			esc := l.advance()
			switch esc {
			case 'n':
				sb.WriteRune('\n')
			case 't':
				sb.WriteRune('\t')
			case 'r':
				sb.WriteRune('\r')
			case '\\':
				sb.WriteRune('\\')
			case '"':
				sb.WriteRune('"')
			case '\'':
				sb.WriteRune('\'')
			default:
				sb.WriteRune('\\')
				sb.WriteRune(esc)
			}
		} else if ch == quote {
			break
		} else {
			sb.WriteRune(ch)
		}
	}
	return sb.String(), nil
}

func (l *Lexer) readNumber() (TokenType, string) {
	var sb strings.Builder
	isFloat := false
	for l.pos < len(l.source) {
		ch := l.peek()
		if unicode.IsDigit(ch) {
			sb.WriteRune(l.advance())
		} else if ch == '.' && !isFloat && unicode.IsDigit(l.peekAt(1)) {
			isFloat = true
			sb.WriteRune(l.advance())
		} else {
			break
		}
	}
	if isFloat {
		return TOKEN_FLOAT, sb.String()
	}
	return TOKEN_INT, sb.String()
}

func (l *Lexer) readIdent() string {
	var sb strings.Builder
	for l.pos < len(l.source) {
		ch := l.peek()
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' {
			sb.WriteRune(l.advance())
		} else {
			break
		}
	}
	return sb.String()
}

// Tokenize converts the source into a slice of tokens
func (l *Lexer) Tokenize() ([]Token, error) {
	for l.pos < len(l.source) {
		l.skipWhitespace()
		if l.pos >= len(l.source) {
			break
		}

		startLine := l.line
		startCol := l.col
		ch := l.peek()

		// Newlines
		if ch == '\n' {
			l.advance()
			l.addToken(TOKEN_NEWLINE, "\\n", startLine, startCol)
			continue
		}

		// Comments: // single line
		if ch == '/' && l.peekAt(1) == '/' {
			for l.pos < len(l.source) && l.peek() != '\n' {
				l.advance()
			}
			continue
		}

		// Comments: /* block */
		if ch == '/' && l.peekAt(1) == '*' {
			l.advance()
			l.advance()
			for l.pos < len(l.source) {
				if l.peek() == '*' && l.peekAt(1) == '/' {
					l.advance()
					l.advance()
					break
				}
				l.advance()
			}
			continue
		}

		// String literals
		if ch == '"' || ch == '\'' {
			quote := l.advance()
			str, err := l.readString(quote)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", startLine, err)
			}
			l.addToken(TOKEN_STRING, str, startLine, startCol)
			continue
		}

		// Numbers
		if unicode.IsDigit(ch) {
			tt, lit := l.readNumber()
			l.addToken(tt, lit, startLine, startCol)
			continue
		}

		// Identifiers & keywords
		if unicode.IsLetter(ch) || ch == '_' {
			ident := l.readIdent()
			if tt, ok := keywords[ident]; ok {
				lit := ident
				if tt == TOKEN_TRUE {
					lit = "true"
				} else if tt == TOKEN_FALSE {
					lit = "false"
				}
				l.addToken(tt, lit, startLine, startCol)
			} else {
				l.addToken(TOKEN_IDENT, ident, startLine, startCol)
			}
			continue
		}

		// Operators and punctuation
		l.advance()
		switch ch {
		case '=':
			if l.peek() == '=' {
				l.advance()
				l.addToken(TOKEN_EQ, "==", startLine, startCol)
			} else {
				l.addToken(TOKEN_ASSIGN, "=", startLine, startCol)
			}
		case '!':
			if l.peek() == '=' {
				l.advance()
				l.addToken(TOKEN_NEQ, "!=", startLine, startCol)
			} else {
				return nil, fmt.Errorf("line %d: unexpected character '!'", startLine)
			}
		case '<':
			if l.peek() == '=' {
				l.advance()
				l.addToken(TOKEN_LTE, "<=", startLine, startCol)
			} else {
				l.addToken(TOKEN_LT, "<", startLine, startCol)
			}
		case '>':
			if l.peek() == '=' {
				l.advance()
				l.addToken(TOKEN_GTE, ">=", startLine, startCol)
			} else {
				l.addToken(TOKEN_GT, ">", startLine, startCol)
			}
		case '+':
			if l.peek() == '+' {
				l.advance()
				l.addToken(TOKEN_INCREMENT, "++", startLine, startCol)
			} else if l.peek() == '=' {
				l.advance()
				l.addToken(TOKEN_PLUSEQ, "+=", startLine, startCol)
			} else {
				l.addToken(TOKEN_PLUS, "+", startLine, startCol)
			}
		case '-':
			if l.peek() == '>' {
				l.advance()
				l.addToken(TOKEN_ARROW, "->", startLine, startCol)
			} else if l.peek() == '-' {
				l.advance()
				l.addToken(TOKEN_DECREMENT, "--", startLine, startCol)
			} else if l.peek() == '=' {
				l.advance()
				l.addToken(TOKEN_MINUSEQ, "-=", startLine, startCol)
			} else {
				l.addToken(TOKEN_MINUS, "-", startLine, startCol)
			}
		case '*':
			l.addToken(TOKEN_STAR, "*", startLine, startCol)
		case '/':
			l.addToken(TOKEN_SLASH, "/", startLine, startCol)
		case '%':
			l.addToken(TOKEN_PERCENT, "%", startLine, startCol)
		case '(':
			l.addToken(TOKEN_LPAREN, "(", startLine, startCol)
		case ')':
			l.addToken(TOKEN_RPAREN, ")", startLine, startCol)
		case '{':
			l.addToken(TOKEN_LBRACE, "{", startLine, startCol)
		case '}':
			l.addToken(TOKEN_RBRACE, "}", startLine, startCol)
		case '[':
			l.addToken(TOKEN_LBRACKET, "[", startLine, startCol)
		case ']':
			l.addToken(TOKEN_RBRACKET, "]", startLine, startCol)
		case ',':
			l.addToken(TOKEN_COMMA, ",", startLine, startCol)
		case '.':
			l.addToken(TOKEN_DOT, ".", startLine, startCol)
		case ':':
			l.addToken(TOKEN_COLON, ":", startLine, startCol)
		case ';':
			l.addToken(TOKEN_SEMI, ";", startLine, startCol)
		case '#':
			// Inline comment style with #
			for l.pos < len(l.source) && l.peek() != '\n' {
				l.advance()
			}
		default:
			return nil, fmt.Errorf("line %d col %d: unexpected character '%c'", startLine, startCol, ch)
		}
	}

	l.addToken(TOKEN_EOF, "", l.line, l.col)
	return l.tokens, nil
}
