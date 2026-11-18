// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

// IssuerNameVariable is the CEL reference to the name of the issuer, in the
// expressions of an issuer of the proxy kind. ADR-0001 gives the reasons for
// this name.
const IssuerNameVariable = issuerVariableRoot + ".issuer.name"

const issuerVariableRoot = "authenticationConfiguration"

// issuerNameReference matches one reference at the start of the text. CEL
// permits whitespace around a dot.
var issuerNameReference = regexp.MustCompile(`^` + issuerVariableRoot + `\s*\.\s*issuer\s*\.\s*name`)

// expandIssuerVariables replaces each reference to IssuerNameVariable in the
// CEL expressions of jwt with a string literal of name. The upstream CEL
// environment does not declare the variable, so the replacement must occur
// before the upstream validation. The error names the field by its path
// below jwt.
func expandIssuerVariables(jwt *apiserverv1.JWTAuthenticator, name string) error {
	type field struct {
		path string
		expr *string
	}
	var fields []field
	for i := range jwt.ClaimValidationRules {
		fields = append(fields, field{fmt.Sprintf("claimValidationRules[%d].expression", i), &jwt.ClaimValidationRules[i].Expression})
	}
	m := &jwt.ClaimMappings
	fields = append(fields,
		field{"claimMappings.username.expression", &m.Username.Expression},
		field{"claimMappings.groups.expression", &m.Groups.Expression},
		field{"claimMappings.uid.expression", &m.UID.Expression},
	)
	for i := range m.Extra {
		fields = append(fields, field{fmt.Sprintf("claimMappings.extra[%d].valueExpression", i), &m.Extra[i].ValueExpression})
	}
	for i := range jwt.UserValidationRules {
		fields = append(fields, field{fmt.Sprintf("userValidationRules[%d].expression", i), &jwt.UserValidationRules[i].Expression})
	}

	for _, f := range fields {
		expanded, err := expandIssuerName(*f.expr, name)
		if err != nil {
			return fmt.Errorf("jwt.%s: %w", f.path, err)
		}
		*f.expr = expanded
	}
	return nil
}

// expandIssuerName returns expr with each reference to IssuerNameVariable
// replaced by a string literal of name. The function finds the references
// in the syntax tree, so the same text in a string literal stays. It returns
// expr unchanged when expr does not parse, because the upstream validation
// then reports the syntax error.
func expandIssuerName(expr, name string) (string, error) {
	if !strings.Contains(expr, issuerVariableRoot) {
		return expr, nil
	}
	p, err := parser.NewParser(parser.Macros(parser.AllMacros...))
	if err != nil {
		return "", err
	}
	tree, errs := p.Parse(common.NewTextSource(expr))
	if len(errs.GetErrors()) > 0 {
		return expr, nil
	}

	// A reference is a select of name on a select of issuer on the root
	// identifier. Each other use of the root identifier is an error.
	matched := map[int64]bool{}
	var roots []ast.Expr
	ast.PreOrderVisit(tree.Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		switch e.Kind() {
		case ast.IdentKind:
			if e.AsIdent() == issuerVariableRoot {
				roots = append(roots, e)
			}
		case ast.SelectKind:
			if root, ok := issuerNameRoot(e); ok {
				matched[root.ID()] = true
			}
		}
	}))

	runes := []rune(expr)
	var starts []int
	for _, root := range roots {
		if !matched[root.ID()] {
			return "", fmt.Errorf("%q is the only field of %q", IssuerNameVariable, issuerVariableRoot)
		}
		r, ok := tree.SourceInfo().GetOffsetRange(root.ID())
		if !ok {
			return "", fmt.Errorf("cannot find %q in the expression", IssuerNameVariable)
		}
		starts = append(starts, int(r.Start))
	}

	// Replace from the end, so that each start offset stays correct.
	slices.Sort(starts)
	literal := []rune(strconv.Quote(name))
	for _, start := range slices.Backward(starts) {
		loc := issuerNameReference.FindStringIndex(string(runes[start:]))
		if loc == nil {
			return "", fmt.Errorf("write %q without comments inside it", IssuerNameVariable)
		}
		end := start + len([]rune(string(runes[start:])[:loc[1]]))
		runes = slices.Concat(runes[:start], literal, runes[end:])
	}
	return string(runes), nil
}

// issuerNameRoot returns the root identifier of e when e is a reference to
// IssuerNameVariable.
func issuerNameRoot(e ast.Expr) (ast.Expr, bool) {
	sel := e.AsSelect()
	if sel.IsTestOnly() || sel.FieldName() != "name" || sel.Operand().Kind() != ast.SelectKind {
		return nil, false
	}
	issuer := sel.Operand().AsSelect()
	if issuer.IsTestOnly() || issuer.FieldName() != "issuer" || issuer.Operand().Kind() != ast.IdentKind {
		return nil, false
	}
	root := issuer.Operand()
	if root.AsIdent() != issuerVariableRoot {
		return nil, false
	}
	return root, true
}
