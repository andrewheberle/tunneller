package regexpflag

import (
	"regexp"

	"github.com/spf13/pflag"
)

var _ pflag.Value = (*Flag)(nil)

type Flag struct {
	r *regexp.Regexp
}

func MustCompile(expr string) *Flag {
	r := regexp.MustCompile(expr)

	return &Flag{r}
}

func Compile(expr string) (*Flag, error) {
	r, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}

	return &Flag{r}, nil
}

func (f *Flag) Set(expr string) error {
	r, err := regexp.Compile(expr)
	if err != nil {
		return err
	}
	f.r = r

	return nil
}

func (f *Flag) String() string {
	return f.r.String()
}

func (f Flag) Type() string {
	return "regexp"
}

func (f *Flag) Regexp() *regexp.Regexp {
	return f.r
}
