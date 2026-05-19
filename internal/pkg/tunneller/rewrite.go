package tunneller

import (
	"bytes"
	"fmt"
	"html/template"
	"regexp"
)

type RewriteContentRule struct {
	re        *regexp.Regexp
	transform func(prefix string, captured []byte) []byte
}

type RewriteContentTemplateData struct {
	Prefix   string
	Captured string
}

func NewRewriteContentRule(reg, tmpl string) (*RewriteContentRule, error) {
	re, err := regexp.Compile(reg)
	if err != nil {
		return nil, err
	}

	if re.NumSubexp() != 1 {
		return nil, fmt.Errorf("rewrite regexp must have one capture group")
	}

	t, err := template.New("rewrite").Parse(tmpl)
	if err != nil {
		return nil, err
	}

	return &RewriteContentRule{
		re: re,
		transform: func(prefix string, captured []byte) []byte {
			buf := new(bytes.Buffer)
			if err := t.Execute(buf, RewriteContentTemplateData{Prefix: prefix, Captured: string(captured)}); err != nil {
				panic(fmt.Sprintf("tunnel: rewrite: %s", err))
			}

			return buf.Bytes()
		},
	}, nil
}
