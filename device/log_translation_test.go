package device

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
	"unicode"
)

func TestDeviceLogMessagesContainChinese(t *testing.T) {
	files, err := parser.ParseDir(token.NewFileSet(), ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files["device"].Files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (selector.Sel.Name != "Errorf" && selector.Sel.Name != "Verbosef") {
				return true
			}
			logger, ok := selector.X.(*ast.SelectorExpr)
			if !ok || logger.Sel.Name != "log" {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Errorf("日志内容必须包含中文固定文本")
				return true
			}
			message, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Errorf("无法解析日志字符串 %s: %v", literal.Value, err)
				return true
			}
			for _, r := range message {
				if unicode.Is(unicode.Han, r) {
					return true
				}
			}
			t.Errorf("日志内容未翻译为中文: %q", message)
			return true
		})
	}
}
