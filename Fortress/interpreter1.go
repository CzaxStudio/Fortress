package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─── Value Types ──────────────────────────────────────────────────────────────

type ValueType string

const (
	ValInt    ValueType = "int"
	ValFloat  ValueType = "float"
	ValString ValueType = "string"
	ValBool   ValueType = "bool"
	ValNull   ValueType = "null"
	ValList   ValueType = "list"
	ValMap    ValueType = "map"
	ValFunc   ValueType = "function"
)

type Value struct {
	Type     ValueType
	IntVal   int64
	FloatVal float64
	StrVal   string
	BoolVal  bool
	ListVal  []*Value
	MapVal   map[string]*Value
	FuncVal  *FuncValue
}

type FuncValue struct {
	Name   string
	Params []string
	Body   []Node
	Env    *Environment
}

var Null = &Value{Type: ValNull}
var True = &Value{Type: ValBool, BoolVal: true}
var False = &Value{Type: ValBool, BoolVal: false}

func intVal(v int64) *Value     { return &Value{Type: ValInt, IntVal: v} }
func floatVal(v float64) *Value { return &Value{Type: ValFloat, FloatVal: v} }
func strVal(s string) *Value    { return &Value{Type: ValString, StrVal: s} }
func boolVal(b bool) *Value {
	if b {
		return True
	}
	return False
}
func listVal(items []*Value) *Value { return &Value{Type: ValList, ListVal: items} }
func mapVal(m map[string]*Value) *Value {
	if m == nil {
		m = make(map[string]*Value)
	}
	return &Value{Type: ValMap, MapVal: m}
}

func (v *Value) Truthy() bool {
	switch v.Type {
	case ValBool:
		return v.BoolVal
	case ValNull:
		return false
	case ValInt:
		return v.IntVal != 0
	case ValFloat:
		return v.FloatVal != 0
	case ValString:
		return v.StrVal != ""
	case ValList:
		return len(v.ListVal) > 0
	case ValMap:
		return len(v.MapVal) > 0
	}
	return true
}

func (v *Value) Display() string {
	switch v.Type {
	case ValNull:
		return "null"
	case ValBool:
		if v.BoolVal {
			return "true"
		}
		return "false"
	case ValInt:
		return fmt.Sprintf("%d", v.IntVal)
	case ValFloat:
		s := strconv.FormatFloat(v.FloatVal, 'f', -1, 64)
		return s
	case ValString:
		return v.StrVal
	case ValList:
		parts := make([]string, len(v.ListVal))
		for i, e := range v.ListVal {
			parts[i] = e.Repr()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case ValMap:
		keys := make([]string, 0, len(v.MapVal))
		for k := range v.MapVal {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s: %s", k, v.MapVal[k].Repr()))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case ValFunc:
		return fmt.Sprintf("<probe %s>", v.FuncVal.Name)
	}
	return "null"
}

func (v *Value) Repr() string {
	if v.Type == ValString {
		return fmt.Sprintf("%q", v.StrVal)
	}
	return v.Display()
}

func (v *Value) ToFloat() float64 {
	switch v.Type {
	case ValInt:
		return float64(v.IntVal)
	case ValFloat:
		return v.FloatVal
	case ValString:
		f, _ := strconv.ParseFloat(v.StrVal, 64)
		return f
	}
	return 0
}

func (v *Value) ToInt() int64 {
	switch v.Type {
	case ValInt:
		return v.IntVal
	case ValFloat:
		return int64(v.FloatVal)
	case ValString:
		i, _ := strconv.ParseInt(v.StrVal, 10, 64)
		return i
	case ValBool:
		if v.BoolVal {
			return 1
		}
		return 0
	}
	return 0
}

// ─── Signal / Control Flow ────────────────────────────────────────────────────

type Signal struct {
	Kind  string // "return", "break", "continue"
	Value *Value
}

func (s *Signal) Error() string { return "signal:" + s.Kind }

// ─── Environment ──────────────────────────────────────────────────────────────

type Environment struct {
	vars   map[string]*Value
	parent *Environment
}

func NewEnvironment(parent *Environment) *Environment {
	return &Environment{vars: make(map[string]*Value), parent: parent}
}

func (e *Environment) Get(name string) (*Value, bool) {
	if v, ok := e.vars[name]; ok {
		return v, true
	}
	if e.parent != nil {
		return e.parent.Get(name)
	}
	return nil, false
}

func (e *Environment) Set(name string, val *Value) {
	if _, ok := e.vars[name]; ok {
		e.vars[name] = val
		return
	}
	if e.parent != nil {
		if e.parent.has(name) {
			e.parent.Set(name, val)
			return
		}
	}
	e.vars[name] = val
}

func (e *Environment) has(name string) bool {
	if _, ok := e.vars[name]; ok {
		return true
	}
	if e.parent != nil {
		return e.parent.has(name)
	}
	return false
}

func (e *Environment) Define(name string, val *Value) {
	e.vars[name] = val
}

// ─── Interpreter ──────────────────────────────────────────────────────────────

type Interpreter struct {
	global  *Environment
	stdin   *bufio.Reader
	httpCli *http.Client
}

func NewInterpreter() *Interpreter {
	interp := &Interpreter{
		global: NewEnvironment(nil),
		stdin:  bufio.NewReader(os.Stdin),
		httpCli: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		},
	}
	interp.registerBuiltins()
	return interp
}

func (interp *Interpreter) registerBuiltins() {
	e := interp.global

	// Standard library functions
	e.Define("len", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "len"}})
	e.Define("str", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "str"}})
	e.Define("int", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "int"}})
	e.Define("float", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "float"}})
	e.Define("bool", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "bool"}})
	e.Define("list", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "list"}})
	e.Define("keys", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "keys"}})
	e.Define("values", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "values"}})
	e.Define("append", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "append"}})
	e.Define("pop", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "pop"}})
	e.Define("contains", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "contains"}})
	e.Define("split", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "split"}})
	e.Define("join", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "join"}})
	e.Define("upper", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "upper"}})
	e.Define("lower", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "lower"}})
	e.Define("trim", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "trim"}})
	e.Define("replace", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "replace"}})
	e.Define("startswith", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "startswith"}})
	e.Define("endswith", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "endswith"}})
	e.Define("slice", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "slice"}})
	e.Define("range", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "range"}})
	e.Define("abs", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "abs"}})
	e.Define("floor", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "floor"}})
	e.Define("ceil", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "ceil"}})
	e.Define("round", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "round"}})
	e.Define("max", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "max"}})
	e.Define("min", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "min"}})
	e.Define("random", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "random"}})
	e.Define("type", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "type"}})
	e.Define("exit", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "exit"}})
	e.Define("sleep", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "sleep"}})
	e.Define("env", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "env"}})
	e.Define("readfile", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "readfile"}})
	e.Define("jsonparse", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "jsonparse"}})
	e.Define("jsondump", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "jsondump"}})
	e.Define("httpget", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "httpget"}})
	e.Define("httppost", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "httppost"}})
	e.Define("isip", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "isip"}})
	e.Define("isipv6", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "isipv6"}})
	e.Define("format", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "format"}})
	e.Define("timestamp", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "timestamp"}})
	e.Define("now", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "now"}})
	e.Define("sort", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "sort"}})
	e.Define("unique", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "unique"}})
	e.Define("haskey", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "haskey"}})
	e.Define("delete", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "delete"}})
	e.Define("merge", &Value{Type: ValFunc, FuncVal: &FuncValue{Name: "merge"}})
}

func (interp *Interpreter) Run(prog *Program) error {
	_, err := interp.execBlock(prog.Statements, interp.global)
	if err != nil {
		if sig, ok := err.(*Signal); ok && sig.Kind == "return" {
			return nil
		}
		return err
	}
	return nil
}

func (interp *Interpreter) execBlock(stmts []Node, env *Environment) (*Value, error) {
	for _, stmt := range stmts {
		val, err := interp.exec(stmt, env)
		if err != nil {
			return nil, err
		}
		if val != nil {
			return val, nil
		}
	}
	return nil, nil
}

func (interp *Interpreter) exec(node Node, env *Environment) (*Value, error) {
	switch n := node.(type) {

	case *LetStatement:
		val, err := interp.eval(n.Value, env)
		if err != nil {
			return nil, err
		}
		env.Define(n.Name, val)
		return nil, nil

	case *AssignStatement:
		val, err := interp.eval(n.Value, env)
		if err != nil {
			return nil, err
		}
		return nil, interp.assign(n.Target, n.Op, val, env)

	case *IncDecStatement:
		return nil, interp.incDec(n.Target, n.Op, env)

	case *ProbeStatement:
		fn := &Value{Type: ValFunc, FuncVal: &FuncValue{
			Name:   n.Name,
			Params: n.Params,
			Body:   n.Body,
			Env:    env,
		}}
		env.Define(n.Name, fn)
		return nil, nil

	case *ReturnStatement:
		var val *Value = Null
		if n.Value != nil {
			var err error
			val, err = interp.eval(n.Value, env)
			if err != nil {
				return nil, err
			}
		}
		return nil, &Signal{Kind: "return", Value: val}

	case *BreakStatement:
		return nil, &Signal{Kind: "break"}

	case *ContinueStatement:
		return nil, &Signal{Kind: "continue"}

	case *ComputeStatement:
		parts := make([]string, 0, len(n.Args))
		for _, arg := range n.Args {
			v, err := interp.eval(arg, env)
			if err != nil {
				return nil, err
			}
			parts = append(parts, v.Display())
		}
		fmt.Println(strings.Join(parts, " "))
		return nil, nil

	case *CaptureStatement:
		var prompt string
		if n.Prompt != nil {
			pv, err := interp.eval(n.Prompt, env)
			if err != nil {
				return nil, err
			}
			prompt = pv.Display()
		}
		fmt.Print(prompt)
		line, _ := interp.stdin.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		env.Define(n.Target, strVal(line))
		return nil, nil

	case *IfStatement:
		cond, err := interp.eval(n.Condition, env)
		if err != nil {
			return nil, err
		}
		if cond.Truthy() {
			child := NewEnvironment(env)
			_, err = interp.execBlock(n.Body, child)
			return nil, err
		}
		for _, elif := range n.ElseIfs {
			ec, err := interp.eval(elif.Condition, env)
			if err != nil {
				return nil, err
			}
			if ec.Truthy() {
				child := NewEnvironment(env)
				_, err = interp.execBlock(elif.Body, child)
				return nil, err
			}
		}
		if n.ElseBody != nil {
			child := NewEnvironment(env)
			_, err = interp.execBlock(n.ElseBody, child)
			return nil, err
		}
		return nil, nil

	case *ScanStatement:
		child := NewEnvironment(env)
		if n.Init != nil {
			if _, err := interp.exec(n.Init, child); err != nil {
				return nil, err
			}
		}
		for {
			if n.Condition != nil {
				cond, err := interp.eval(n.Condition, child)
				if err != nil {
					return nil, err
				}
				if !cond.Truthy() {
					break
				}
			}
			iter := NewEnvironment(child)
			_, err := interp.execBlock(n.Body, iter)
			if err != nil {
				if sig, ok := err.(*Signal); ok {
					if sig.Kind == "break" {
						break
					}
					if sig.Kind == "continue" {
						// run post and continue
					} else {
						return nil, err
					}
				} else {
					return nil, err
				}
			}
			if n.Post != nil {
				if _, err := interp.exec(n.Post, child); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil

	case *EachStatement:
		coll, err := interp.eval(n.Collection, env)
		if err != nil {
			return nil, err
		}
		var items []*Value
		switch coll.Type {
		case ValList:
			items = coll.ListVal
		case ValMap:
			for k := range coll.MapVal {
				items = append(items, strVal(k))
			}
			sort.Slice(items, func(i, j int) bool {
				return items[i].StrVal < items[j].StrVal
			})
		case ValString:
			for _, ch := range coll.StrVal {
				items = append(items, strVal(string(ch)))
			}
		default:
			return nil, fmt.Errorf("cannot iterate over %s", coll.Type)
		}
		for _, item := range items {
			iter := NewEnvironment(env)
			iter.Define(n.Var, item)
			_, err := interp.execBlock(n.Body, iter)
			if err != nil {
				if sig, ok := err.(*Signal); ok {
					if sig.Kind == "break" {
						break
					}
					if sig.Kind == "continue" {
						continue
					}
					return nil, err
				}
				return nil, err
			}
		}
		return nil, nil

	case *UntilStatement:
		for {
			cond, err := interp.eval(n.Condition, env)
			if err != nil {
				return nil, err
			}
			if !cond.Truthy() {
				break
			}
			iter := NewEnvironment(env)
			_, err = interp.execBlock(n.Body, iter)
			if err != nil {
				if sig, ok := err.(*Signal); ok {
					if sig.Kind == "break" {
						break
					}
					if sig.Kind == "continue" {
						continue
					}
					return nil, err
				}
				return nil, err
			}
		}
		return nil, nil

	case *ImportStatement:
		// Load a Fortress library installed via 'fortress get site=<n>'
		stmts, libErr := LoadLibrary(n.Module, n.Alias)
		if libErr != nil {
			return nil, fmt.Errorf("line %d: %v", n.Line, libErr)
		}
		// Evaluate all library statements in a fresh child environment
		libEnv := NewEnvironment(env)
		for _, s := range stmts {
			if _, execErr := interp.exec(s, libEnv); execErr != nil {
				return nil, fmt.Errorf("line %d: error in library '%s': %v", n.Line, n.Module, execErr)
			}
		}
		// Expose all top-level definitions (probes, lets) under the alias as a map
		m := make(map[string]*Value)
		for k, v := range libEnv.vars {
			m[k] = v
		}
		env.Define(n.Alias, mapVal(m))
		return nil, nil

	case *ReportStatement:
		return nil, interp.execReport(n, env)

	case *SaveStatement:
		return nil, interp.execSave(n, env)

	case *ExprStatement:
		_, err := interp.eval(n.Expr, env)
		return nil, err
	}

	return nil, fmt.Errorf("unknown statement: %T", node)
}

func (interp *Interpreter) assign(target Node, op string, val *Value, env *Environment) error {
	switch t := target.(type) {
	case *Identifier:
		if op == "=" {
			env.Set(t.Name, val)
		} else {
			cur, ok := env.Get(t.Name)
			if !ok {
				return fmt.Errorf("undefined variable: %s", t.Name)
			}
			nv, err := interp.applyArith(cur, op[:1], val)
			if err != nil {
				return err
			}
			env.Set(t.Name, nv)
		}
	case *IndexExpr:
		obj, err := interp.eval(t.Object, env)
		if err != nil {
			return err
		}
		idx, err := interp.eval(t.Index, env)
		if err != nil {
			return err
		}
		switch obj.Type {
		case ValList:
			i := int(idx.ToInt())
			if i < 0 || i >= len(obj.ListVal) {
				return fmt.Errorf("index out of range: %d", i)
			}
			obj.ListVal[i] = val
		case ValMap:
			obj.MapVal[idx.Display()] = val
		default:
			return fmt.Errorf("cannot index %s", obj.Type)
		}
	case *MemberExpr:
		obj, err := interp.eval(t.Object, env)
		if err != nil {
			return err
		}
		if obj.Type != ValMap {
			return fmt.Errorf("cannot set field on %s", obj.Type)
		}
		obj.MapVal[t.Field] = val
	default:
		return fmt.Errorf("invalid assignment target")
	}
	return nil
}

func (interp *Interpreter) incDec(target Node, op string, env *Environment) error {
	ident, ok := target.(*Identifier)
	if !ok {
		return fmt.Errorf("++ / -- only valid on identifiers")
	}
	cur, found := env.Get(ident.Name)
	if !found {
		return fmt.Errorf("undefined variable: %s", ident.Name)
	}
	if op == "++" {
		if cur.Type == ValFloat {
			env.Set(ident.Name, floatVal(cur.FloatVal+1))
		} else {
			env.Set(ident.Name, intVal(cur.IntVal+1))
		}
	} else {
		if cur.Type == ValFloat {
			env.Set(ident.Name, floatVal(cur.FloatVal-1))
		} else {
			env.Set(ident.Name, intVal(cur.IntVal-1))
		}
	}
	return nil
}

// ─── Eval ─────────────────────────────────────────────────────────────────────

func (interp *Interpreter) eval(node Node, env *Environment) (*Value, error) {
	switch n := node.(type) {
	case *IntLiteral:
		return intVal(n.Value), nil
	case *FloatLiteral:
		return floatVal(n.Value), nil
	case *StringLiteral:
		return strVal(n.Value), nil
	case *BoolLiteral:
		return boolVal(n.Value), nil
	case *NullLiteral:
		return Null, nil

	case *Identifier:
		v, ok := env.Get(n.Name)
		if !ok {
			return nil, fmt.Errorf("line %d: undefined variable '%s'", n.Line, n.Name)
		}
		return v, nil

	case *ListLiteral:
		items := make([]*Value, 0, len(n.Elements))
		for _, e := range n.Elements {
			v, err := interp.eval(e, env)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return listVal(items), nil

	case *MapLiteral:
		m := make(map[string]*Value)
		for _, pair := range n.Pairs {
			k, err := interp.eval(pair.Key, env)
			if err != nil {
				return nil, err
			}
			v, err := interp.eval(pair.Value, env)
			if err != nil {
				return nil, err
			}
			m[k.Display()] = v
		}
		return mapVal(m), nil

	case *BinaryExpr:
		return interp.evalBinary(n, env)

	case *UnaryExpr:
		return interp.evalUnary(n, env)

	case *ConcatExpr:
		left, err := interp.eval(n.Left, env)
		if err != nil {
			return nil, err
		}
		right, err := interp.eval(n.Right, env)
		if err != nil {
			return nil, err
		}
		return strVal(left.Display() + right.Display()), nil

	case *IndexExpr:
		obj, err := interp.eval(n.Object, env)
		if err != nil {
			return nil, err
		}
		idx, err := interp.eval(n.Index, env)
		if err != nil {
			return nil, err
		}
		switch obj.Type {
		case ValList:
			i := int(idx.ToInt())
			if i < 0 || i >= len(obj.ListVal) {
				return Null, nil
			}
			return obj.ListVal[i], nil
		case ValMap:
			v, ok := obj.MapVal[idx.Display()]
			if !ok || v == nil {
				return Null, nil
			}
			return v, nil
		case ValString:
			i := int(idx.ToInt())
			runes := []rune(obj.StrVal)
			if i < 0 || i >= len(runes) {
				return Null, nil
			}
			return strVal(string(runes[i])), nil
		}
		return nil, fmt.Errorf("cannot index %s", obj.Type)

	case *MemberExpr:
		obj, err := interp.eval(n.Object, env)
		if err != nil {
			return nil, err
		}
		if obj == nil || obj.Type == ValNull {
			return Null, nil
		}
		if obj.Type == ValMap {
			v, ok := obj.MapVal[n.Field]
			if !ok || v == nil {
				return Null, nil
			}
			return v, nil
		}
		return nil, fmt.Errorf("cannot access field '%s' on %s", n.Field, obj.Type)

	case *CallExpr:
		return interp.evalCall(n, env)

	case *BuiltinCall:
		return interp.evalNetBuiltin(n, env)
	}

	return nil, fmt.Errorf("cannot evaluate node: %T", node)
}

func (interp *Interpreter) evalBinary(n *BinaryExpr, env *Environment) (*Value, error) {
	left, err := interp.eval(n.Left, env)
	if err != nil {
		return nil, err
	}

	// Short-circuit for logical ops
	if n.Op == "and" {
		if !left.Truthy() {
			return False, nil
		}
		right, err := interp.eval(n.Right, env)
		if err != nil {
			return nil, err
		}
		return boolVal(right.Truthy()), nil
	}
	if n.Op == "or" {
		if left.Truthy() {
			return True, nil
		}
		right, err := interp.eval(n.Right, env)
		if err != nil {
			return nil, err
		}
		return boolVal(right.Truthy()), nil
	}

	right, err := interp.eval(n.Right, env)
	if err != nil {
		return nil, err
	}

	switch n.Op {
	case "==":
		return boolVal(valEqual(left, right)), nil
	case "!=":
		return boolVal(!valEqual(left, right)), nil
	case "<":
		return boolVal(valCompare(left, right) < 0), nil
	case "<=":
		return boolVal(valCompare(left, right) <= 0), nil
	case ">":
		return boolVal(valCompare(left, right) > 0), nil
	case ">=":
		return boolVal(valCompare(left, right) >= 0), nil
	case "+", "-", "*", "/", "%":
		return interp.applyArith(left, n.Op, right)
	}
	return nil, fmt.Errorf("unknown operator: %s", n.Op)
}

func (interp *Interpreter) applyArith(left *Value, op string, right *Value) (*Value, error) {
	// String concatenation with +
	if op == "+" && (left.Type == ValString || right.Type == ValString) {
		return strVal(left.Display() + right.Display()), nil
	}
	// List concat
	if op == "+" && left.Type == ValList && right.Type == ValList {
		combined := make([]*Value, len(left.ListVal)+len(right.ListVal))
		copy(combined, left.ListVal)
		copy(combined[len(left.ListVal):], right.ListVal)
		return listVal(combined), nil
	}
	// Numeric
	lf := left.ToFloat()
	rf := right.ToFloat()
	var result float64
	switch op {
	case "+":
		result = lf + rf
	case "-":
		result = lf - rf
	case "*":
		result = lf * rf
	case "/":
		if rf == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		result = lf / rf
	case "%":
		li := left.ToInt()
		ri := right.ToInt()
		if ri == 0 {
			return nil, fmt.Errorf("modulo by zero")
		}
		return intVal(li % ri), nil
	}
	if left.Type == ValInt && right.Type == ValInt && op != "/" {
		return intVal(int64(result)), nil
	}
	return floatVal(result), nil
}

func (interp *Interpreter) evalUnary(n *UnaryExpr, env *Environment) (*Value, error) {
	v, err := interp.eval(n.Operand, env)
	if err != nil {
		return nil, err
	}
	switch n.Op {
	case "-":
		if v.Type == ValFloat {
			return floatVal(-v.FloatVal), nil
		}
		return intVal(-v.IntVal), nil
	case "not":
		return boolVal(!v.Truthy()), nil
	}
	return nil, fmt.Errorf("unknown unary op: %s", n.Op)
}

func valEqual(a, b *Value) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Type != b.Type {
		if (a.Type == ValInt || a.Type == ValFloat) && (b.Type == ValInt || b.Type == ValFloat) {
			return a.ToFloat() == b.ToFloat()
		}
		// null == null already handled above; null != anything else
		if a.Type == ValNull || b.Type == ValNull {
			return false
		}
		return false
	}
	switch a.Type {
	case ValNull:
		return true
	case ValBool:
		return a.BoolVal == b.BoolVal
	case ValInt:
		return a.IntVal == b.IntVal
	case ValFloat:
		return a.FloatVal == b.FloatVal
	case ValString:
		return a.StrVal == b.StrVal
	}
	return false
}

func valCompare(a, b *Value) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	af := a.ToFloat()
	bf := b.ToFloat()
	if a.Type == ValString && b.Type == ValString {
		return strings.Compare(a.StrVal, b.StrVal)
	}
	if af < bf {
		return -1
	}
	if af > bf {
		return 1
	}
	return 0
}

// mapGetStr safely retrieves a string value from a map, returning strVal("") if missing.
func mapGetStr(m map[string]*Value, key string) *Value {
	if v, ok := m[key]; ok && v != nil {
		return v
	}
	return strVal("")
}

// ─── Function Calls ───────────────────────────────────────────────────────────

func (interp *Interpreter) evalCall(n *CallExpr, env *Environment) (*Value, error) {
	callee, err := interp.eval(n.Callee, env)
	if err != nil {
		return nil, err
	}
	if callee.Type != ValFunc {
		return nil, fmt.Errorf("line %d: %s is not callable", n.Line, n.Callee.String())
	}

	args := make([]*Value, 0, len(n.Args))
	for _, a := range n.Args {
		v, err := interp.eval(a, env)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}

	fn := callee.FuncVal

	// Built-in functions (no body)
	if fn.Body == nil {
		return interp.callBuiltin(fn.Name, args, n.Line)
	}

	// User-defined probe
	if len(args) != len(fn.Params) {
		return nil, fmt.Errorf("line %d: %s expects %d args, got %d", n.Line, fn.Name, len(fn.Params), len(args))
	}
	child := NewEnvironment(fn.Env)
	for i, param := range fn.Params {
		child.Define(param, args[i])
	}
	_, err = interp.execBlock(fn.Body, child)
	if err != nil {
		if sig, ok := err.(*Signal); ok && sig.Kind == "return" {
			if sig.Value != nil {
				return sig.Value, nil
			}
			return Null, nil
		}
		return nil, err
	}
	return Null, nil
}

func (interp *Interpreter) callBuiltin(name string, args []*Value, line int) (*Value, error) {
	switch name {
	case "len":
		if len(args) != 1 {
			return nil, fmt.Errorf("len() takes 1 argument")
		}
		switch args[0].Type {
		case ValString:
			return intVal(int64(len([]rune(args[0].StrVal)))), nil
		case ValList:
			return intVal(int64(len(args[0].ListVal))), nil
		case ValMap:
			return intVal(int64(len(args[0].MapVal))), nil
		}
		return intVal(0), nil

	case "str":
		if len(args) != 1 {
			return nil, fmt.Errorf("str() takes 1 argument")
		}
		return strVal(args[0].Display()), nil

	case "int":
		if len(args) != 1 {
			return nil, fmt.Errorf("int() takes 1 argument")
		}
		return intVal(args[0].ToInt()), nil

	case "float":
		if len(args) != 1 {
			return nil, fmt.Errorf("float() takes 1 argument")
		}
		return floatVal(args[0].ToFloat()), nil

	case "bool":
		if len(args) != 1 {
			return nil, fmt.Errorf("bool() takes 1 argument")
		}
		return boolVal(args[0].Truthy()), nil

	case "list":
		if len(args) == 0 {
			return listVal([]*Value{}), nil
		}
		if args[0].Type == ValList {
			return args[0], nil
		}
		return listVal([]*Value{args[0]}), nil

	case "keys":
		if len(args) != 1 || args[0].Type != ValMap {
			return nil, fmt.Errorf("keys() takes a map")
		}
		keys := make([]*Value, 0, len(args[0].MapVal))
		for k := range args[0].MapVal {
			keys = append(keys, strVal(k))
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].StrVal < keys[j].StrVal })
		return listVal(keys), nil

	case "values":
		if len(args) != 1 || args[0].Type != ValMap {
			return nil, fmt.Errorf("values() takes a map")
		}
		keys := make([]string, 0, len(args[0].MapVal))
		for k := range args[0].MapVal {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		vals := make([]*Value, 0, len(keys))
		for _, k := range keys {
			vals = append(vals, args[0].MapVal[k])
		}
		return listVal(vals), nil

	case "append":
		if len(args) < 2 {
			return nil, fmt.Errorf("append() takes at least 2 args")
		}
		if args[0].Type != ValList {
			return nil, fmt.Errorf("append() first arg must be list")
		}
		args[0].ListVal = append(args[0].ListVal, args[1:]...)
		return args[0], nil

	case "pop":
		if len(args) != 1 || args[0].Type != ValList {
			return nil, fmt.Errorf("pop() takes a list")
		}
		l := args[0].ListVal
		if len(l) == 0 {
			return Null, nil
		}
		last := l[len(l)-1]
		args[0].ListVal = l[:len(l)-1]
		return last, nil

	case "contains":
		if len(args) != 2 {
			return nil, fmt.Errorf("contains() takes 2 args")
		}
		switch args[0].Type {
		case ValString:
			return boolVal(strings.Contains(args[0].StrVal, args[1].Display())), nil
		case ValList:
			for _, item := range args[0].ListVal {
				if valEqual(item, args[1]) {
					return True, nil
				}
			}
			return False, nil
		case ValMap:
			_, ok := args[0].MapVal[args[1].Display()]
			return boolVal(ok), nil
		}
		return False, nil

	case "split":
		if len(args) < 1 {
			return nil, fmt.Errorf("split() takes 1-2 args")
		}
		sep := " "
		if len(args) >= 2 {
			sep = args[1].Display()
		}
		parts := strings.Split(args[0].Display(), sep)
		items := make([]*Value, len(parts))
		for i, p := range parts {
			items[i] = strVal(p)
		}
		return listVal(items), nil

	case "join":
		if len(args) < 1 {
			return nil, fmt.Errorf("join() takes 1-2 args")
		}
		sep := ""
		if len(args) >= 2 {
			sep = args[1].Display()
		}
		if args[0].Type != ValList {
			return nil, fmt.Errorf("join() first arg must be list")
		}
		parts := make([]string, len(args[0].ListVal))
		for i, v := range args[0].ListVal {
			parts[i] = v.Display()
		}
		return strVal(strings.Join(parts, sep)), nil

	case "upper":
		if len(args) != 1 {
			return nil, fmt.Errorf("upper() takes 1 arg")
		}
		return strVal(strings.ToUpper(args[0].Display())), nil

	case "lower":
		if len(args) != 1 {
			return nil, fmt.Errorf("lower() takes 1 arg")
		}
		return strVal(strings.ToLower(args[0].Display())), nil

	case "trim":
		if len(args) != 1 {
			return nil, fmt.Errorf("trim() takes 1 arg")
		}
		return strVal(strings.TrimSpace(args[0].Display())), nil

	case "replace":
		if len(args) != 3 {
			return nil, fmt.Errorf("replace() takes 3 args: str, old, new")
		}
		return strVal(strings.ReplaceAll(args[0].Display(), args[1].Display(), args[2].Display())), nil

	case "startswith":
		if len(args) != 2 {
			return nil, fmt.Errorf("startswith() takes 2 args")
		}
		return boolVal(strings.HasPrefix(args[0].Display(), args[1].Display())), nil

	case "endswith":
		if len(args) != 2 {
			return nil, fmt.Errorf("endswith() takes 2 args")
		}
		return boolVal(strings.HasSuffix(args[0].Display(), args[1].Display())), nil

	case "slice":
		if len(args) < 2 {
			return nil, fmt.Errorf("slice() takes 2-3 args")
		}
		if args[0].Type == ValList {
			l := args[0].ListVal
			start := int(args[1].ToInt())
			end := len(l)
			if len(args) >= 3 {
				end = int(args[2].ToInt())
			}
			if start < 0 {
				start = 0
			}
			if end > len(l) {
				end = len(l)
			}
			return listVal(l[start:end]), nil
		}
		s := []rune(args[0].Display())
		start := int(args[1].ToInt())
		end := len(s)
		if len(args) >= 3 {
			end = int(args[2].ToInt())
		}
		if start < 0 {
			start = 0
		}
		if end > len(s) {
			end = len(s)
		}
		return strVal(string(s[start:end])), nil

	case "range":
		if len(args) < 1 {
			return nil, fmt.Errorf("range() takes 1-3 args")
		}
		start := int64(0)
		end := args[0].ToInt()
		step := int64(1)
		if len(args) >= 2 {
			start = args[0].ToInt()
			end = args[1].ToInt()
		}
		if len(args) >= 3 {
			step = args[2].ToInt()
		}
		if step == 0 {
			return nil, fmt.Errorf("range() step cannot be zero")
		}
		var items []*Value
		for i := start; (step > 0 && i < end) || (step < 0 && i > end); i += step {
			items = append(items, intVal(i))
		}
		return listVal(items), nil

	case "abs":
		if len(args) != 1 {
			return nil, fmt.Errorf("abs() takes 1 arg")
		}
		if args[0].Type == ValFloat {
			return floatVal(math.Abs(args[0].FloatVal)), nil
		}
		v := args[0].ToInt()
		if v < 0 {
			return intVal(-v), nil
		}
		return intVal(v), nil

	case "floor":
		if len(args) != 1 {
			return nil, fmt.Errorf("floor() takes 1 arg")
		}
		return intVal(int64(math.Floor(args[0].ToFloat()))), nil

	case "ceil":
		if len(args) != 1 {
			return nil, fmt.Errorf("ceil() takes 1 arg")
		}
		return intVal(int64(math.Ceil(args[0].ToFloat()))), nil

	case "round":
		if len(args) != 1 {
			return nil, fmt.Errorf("round() takes 1 arg")
		}
		return intVal(int64(math.Round(args[0].ToFloat()))), nil

	case "max":
		if len(args) == 0 {
			return Null, nil
		}
		if len(args) == 1 && args[0].Type == ValList {
			if len(args[0].ListVal) == 0 {
				return Null, nil
			}
			m := args[0].ListVal[0]
			for _, v := range args[0].ListVal[1:] {
				if valCompare(v, m) > 0 {
					m = v
				}
			}
			return m, nil
		}
		m := args[0]
		for _, v := range args[1:] {
			if valCompare(v, m) > 0 {
				m = v
			}
		}
		return m, nil

	case "min":
		if len(args) == 0 {
			return Null, nil
		}
		if len(args) == 1 && args[0].Type == ValList {
			if len(args[0].ListVal) == 0 {
				return Null, nil
			}
			m := args[0].ListVal[0]
			for _, v := range args[0].ListVal[1:] {
				if valCompare(v, m) < 0 {
					m = v
				}
			}
			return m, nil
		}
		m := args[0]
		for _, v := range args[1:] {
			if valCompare(v, m) < 0 {
				m = v
			}
		}
		return m, nil

	case "random":
		return floatVal(rand.Float64()), nil

	case "type":
		if len(args) != 1 {
			return nil, fmt.Errorf("type() takes 1 arg")
		}
		return strVal(string(args[0].Type)), nil

	case "exit":
		code := 0
		if len(args) > 0 {
			code = int(args[0].ToInt())
		}
		os.Exit(code)
		return Null, nil

	case "sleep":
		if len(args) != 1 {
			return nil, fmt.Errorf("sleep() takes 1 arg (seconds)")
		}
		ms := int64(args[0].ToFloat() * 1000)
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return Null, nil

	case "env":
		if len(args) != 1 {
			return nil, fmt.Errorf("env() takes 1 arg")
		}
		return strVal(os.Getenv(args[0].Display())), nil

	case "readfile":
		if len(args) != 1 {
			return nil, fmt.Errorf("readfile() takes 1 arg")
		}
		data, err := os.ReadFile(args[0].Display())
		if err != nil {
			return Null, nil
		}
		return strVal(string(data)), nil

	case "jsonparse":
		if len(args) != 1 {
			return nil, fmt.Errorf("jsonparse() takes 1 arg")
		}
		var raw interface{}
		if err := json.Unmarshal([]byte(args[0].Display()), &raw); err != nil {
			return Null, nil
		}
		return jsonToValue(raw), nil

	case "jsondump":
		if len(args) != 1 {
			return nil, fmt.Errorf("jsondump() takes 1 arg")
		}
		b, err := json.MarshalIndent(valueToJSON(args[0]), "", "  ")
		if err != nil {
			return Null, nil
		}
		return strVal(string(b)), nil

	case "httpget":
		if len(args) < 1 {
			return nil, fmt.Errorf("httpget() takes 1-2 args")
		}
		url := args[0].Display()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return mapVal(map[string]*Value{"error": strVal(err.Error()), "status": intVal(0), "body": strVal("")}), nil
		}
		if len(args) >= 2 && args[1].Type == ValMap {
			for k, v := range args[1].MapVal {
				req.Header.Set(k, v.Display())
			}
		}
		req.Header.Set("User-Agent", "Fortress/1.0 OSINT-Engine")
		resp, err := interp.httpCli.Do(req)
		if err != nil {
			return mapVal(map[string]*Value{"error": strVal(err.Error()), "status": intVal(0), "body": strVal("")}), nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		hdrs := make(map[string]*Value)
		for k, v := range resp.Header {
			hdrs[k] = strVal(strings.Join(v, ", "))
		}
		return mapVal(map[string]*Value{
			"status":  intVal(int64(resp.StatusCode)),
			"body":    strVal(string(body)),
			"headers": mapVal(hdrs),
			"error":   strVal(""),
		}), nil

	case "httppost":
		if len(args) < 2 {
			return nil, fmt.Errorf("httppost() takes 2+ args")
		}
		url := args[0].Display()
		body := args[1].Display()
		resp, err := interp.httpCli.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			return mapVal(map[string]*Value{"error": strVal(err.Error()), "status": intVal(0), "body": strVal("")}), nil
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return mapVal(map[string]*Value{
			"status": intVal(int64(resp.StatusCode)),
			"body":   strVal(string(rb)),
			"error":  strVal(""),
		}), nil

	case "isip":
		if len(args) != 1 {
			return nil, fmt.Errorf("isip() takes 1 arg")
		}
		ip := net.ParseIP(args[0].Display())
		return boolVal(ip != nil && ip.To4() != nil), nil

	case "isipv6":
		if len(args) != 1 {
			return nil, fmt.Errorf("isipv6() takes 1 arg")
		}
		ip := net.ParseIP(args[0].Display())
		return boolVal(ip != nil && ip.To4() == nil), nil

	case "format":
		if len(args) < 1 {
			return nil, fmt.Errorf("format() takes at least 1 arg")
		}
		fmtStr := args[0].Display()
		ifaces := make([]interface{}, len(args)-1)
		for i, a := range args[1:] {
			ifaces[i] = a.Display()
		}
		return strVal(fmt.Sprintf(fmtStr, ifaces...)), nil

	case "timestamp":
		return intVal(time.Now().Unix()), nil

	case "now":
		return strVal(time.Now().Format("2006-01-02 15:04:05 MST")), nil

	case "sort":
		if len(args) != 1 || args[0].Type != ValList {
			return nil, fmt.Errorf("sort() takes a list")
		}
		items := make([]*Value, len(args[0].ListVal))
		copy(items, args[0].ListVal)
		sort.Slice(items, func(i, j int) bool {
			return valCompare(items[i], items[j]) < 0
		})
		return listVal(items), nil

	case "unique":
		if len(args) != 1 || args[0].Type != ValList {
			return nil, fmt.Errorf("unique() takes a list")
		}
		seen := make(map[string]bool)
		var result []*Value
		for _, item := range args[0].ListVal {
			key := item.Repr()
			if !seen[key] {
				seen[key] = true
				result = append(result, item)
			}
		}
		return listVal(result), nil

	case "haskey":
		if len(args) != 2 || args[0].Type != ValMap {
			return nil, fmt.Errorf("haskey() takes a map and a key")
		}
		_, ok := args[0].MapVal[args[1].Display()]
		return boolVal(ok), nil

	case "delete":
		if len(args) != 2 || args[0].Type != ValMap {
			return nil, fmt.Errorf("delete() takes a map and a key")
		}
		delete(args[0].MapVal, args[1].Display())
		return Null, nil

	case "merge":
		if len(args) < 2 {
			return nil, fmt.Errorf("merge() takes 2+ maps")
		}
		result := make(map[string]*Value)
		for _, a := range args {
			if a.Type != ValMap {
				return nil, fmt.Errorf("merge() all args must be maps")
			}
			for k, v := range a.MapVal {
				result[k] = v
			}
		}
		return mapVal(result), nil
	}

	return nil, fmt.Errorf("line %d: unknown builtin '%s'", line, name)
}

// ─── Report Statement ─────────────────────────────────────────────────────────

func (interp *Interpreter) execReport(n *ReportStatement, env *Environment) error {
	title, err := interp.eval(n.Title, env)
	if err != nil {
		return err
	}
	format := "text"
	if n.Format != nil {
		fv, err2 := interp.eval(n.Format, env)
		if err2 != nil {
			return err2
		}
		format = strings.ToLower(fv.Display())
	}

	type kv struct {
		label string
		val   *Value
	}
	fields := make([]kv, 0, len(n.Fields))
	for _, f := range n.Fields {
		v, err2 := interp.eval(f.Value, env)
		if err2 != nil {
			return err2
		}
		fields = append(fields, kv{f.Label, v})
	}

	switch format {
	case "json":
		m := make(map[string]*Value)
		m["_title"] = title
		m["_timestamp"] = strVal(time.Now().Format(time.RFC3339))
		for _, f := range fields {
			m[f.label] = f.val
		}
		b, _ := json.MarshalIndent(valueToJSON(mapVal(m)), "", "  ")
		fmt.Println(string(b))

	case "html":
		fmt.Printf("<!DOCTYPE html><html><head><title>%s</title>\n", title.Display())
		fmt.Print("<style>body{font-family:monospace;background:#0a0a0a;color:#00ff88;padding:20px}")
		fmt.Print("h1{color:#00ffff;border-bottom:1px solid #00ff88}")
		fmt.Print("table{width:100%;border-collapse:collapse}")
		fmt.Print("td,th{padding:8px;border:1px solid #333;text-align:left}")
		fmt.Println("th{background:#111;color:#00ffff}.val{color:#ffcc00}</style></head><body>")
		fmt.Printf("<h1>FORTRESS REPORT: %s</h1>\n", title.Display())
		fmt.Printf("<p style=\"color:#666\">Generated: %s</p><table><tr><th>Field</th><th>Value</th></tr>\n",
			time.Now().Format(time.RFC3339))
		for _, f := range fields {
			fmt.Printf("<tr><td>%s</td><td class=\"val\">%s</td></tr>\n", f.label, f.val.Display())
		}
		fmt.Println("</table></body></html>")

	default: // text
		border := strings.Repeat("═", 60)
		fmt.Println("  ╔" + border + "╗")
		fmt.Printf("  ║  %-58s║\n", "FORTRESS REPORT: "+title.Display())
		fmt.Printf("  ║  %-58s║\n", "Generated: "+time.Now().Format("2006-01-02 15:04:05"))
		fmt.Println("  ╠" + border + "╣")
		for _, f := range fields {
			label := fmt.Sprintf("  %-20s", f.label)
			val := f.val.Display()
			if len(val) > 36 {
				fmt.Printf("  ║%s │ %-36s║\n", label, val[:36])
				for i := 36; i < len(val); i += 36 {
					end := i + 36
					if end > len(val) {
						end = len(val)
					}
					fmt.Printf("  ║%-22s │ %-36s║\n", "", val[i:end])
				}
			} else {
				fmt.Printf("  ║%s │ %-36s║\n", label, val)
			}
		}
		fmt.Println("  ╚" + border + "╝")
	}
	return nil
}

// ─── Save Statement ───────────────────────────────────────────────────────────

func (interp *Interpreter) execSave(n *SaveStatement, env *Environment) error {
	data, err := interp.eval(n.Data, env)
	if err != nil {
		return err
	}
	filename, err2 := interp.eval(n.Filename, env)
	if err2 != nil {
		return err2
	}
	content := data.Display()
	if err3 := os.WriteFile(filename.Display(), []byte(content), 0644); err3 != nil {
		return fmt.Errorf("save: %v", err3)
	}
	fmt.Printf("  ✔ Saved to %s (%d bytes)\n", filename.Display(), len(content))
	return nil
}

// ─── JSON Helpers ─────────────────────────────────────────────────────────────

func jsonToValue(raw interface{}) *Value {
	if raw == nil {
		return Null
	}
	switch v := raw.(type) {
	case bool:
		return boolVal(v)
	case float64:
		if v == float64(int64(v)) {
			return intVal(int64(v))
		}
		return floatVal(v)
	case string:
		return strVal(v)
	case []interface{}:
		items := make([]*Value, len(v))
		for i, e := range v {
			items[i] = jsonToValue(e)
		}
		return listVal(items)
	case map[string]interface{}:
		m := make(map[string]*Value)
		for k, val := range v {
			m[k] = jsonToValue(val)
		}
		return mapVal(m)
	}
	return strVal(fmt.Sprintf("%v", raw))
}

func valueToJSON(v *Value) interface{} {
	if v == nil {
		return nil
	}
	switch v.Type {
	case ValNull:
		return nil
	case ValBool:
		return v.BoolVal
	case ValInt:
		return v.IntVal
	case ValFloat:
		return v.FloatVal
	case ValString:
		return v.StrVal
	case ValList:
		items := make([]interface{}, len(v.ListVal))
		for i, e := range v.ListVal {
			items[i] = valueToJSON(e)
		}
		return items
	case ValMap:
		m := make(map[string]interface{})
		for k, val := range v.MapVal {
			m[k] = valueToJSON(val)
		}
		return m
	}
	return nil
}
