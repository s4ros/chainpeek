package iptables

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Loader interface {
	Load() (ParseResult, error)
}

type FileLoader struct{ Path string }

func (l FileLoader) Load() (ParseResult, error) {
	f, err := os.Open(l.Path)
	if err != nil {
		return ParseResult{}, err
	}
	defer f.Close()
	return Parse(f)
}

type CmdLoader struct {
	Name string
	Args []string
}

func DefaultCmdLoader() CmdLoader {
	return CmdLoader{Name: "iptables-save"}
}

func (l CmdLoader) Load() (ParseResult, error) {
	name := l.Name
	if name == "" {
		name = "iptables-save"
	}
	cmd := exec.Command(name, l.Args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return ParseResult{}, fmt.Errorf("chainpeek: cannot read live rules: %s", msg)
	}
	return Parse(&stdout)
}
