// 模板渲染健全性检查（由 assessment/validate.sh 调用）：
//   bash assessment/validate.sh
// 用完整模拟参数渲染 prompts/ 下三个覆盖模板，检查语法、分支与未解析变量。
package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"
)

type check struct {
	name   string
	vars   map[string]any
	forbid []string // 渲染结果中不允许出现的痕迹
}

func main() {
	s := func(vals ...string) map[string]any {
		m := map[string]any{}
		for _, v := range vals {
			m[v] = "X"
		}
		return m
	}
	checks := []check{
		{"prompts/image_chooser.tmpl", s("DefaultImage", "DefaultImageForPentest", "Input"), []string{"<no value>"}},
		{"prompts/pentester.tmpl", s(
			"HackResultToolName", "WebSearchToolName", "SearchGuideToolName", "StoreGuideToolName",
			"GraphitiSearchToolName", "SearchToolName", "CoderToolName", "AdviceToolName",
			"MemoristToolName", "MaintenanceToolName", "TerminalToolName", "VulnScanToolName", "FileToolName",
			"SummarizationToolName", "SummarizedContentPrefix", "IsDefaultDockerImage",
			"DockerImage", "Cwd", "ContainerPorts", "ExecutionContext", "Lang",
			"CurrentTime", "ToolPlaceholder", "UserFiles",
		), []string{"<no value>"}},
		{"prompts/reporter.tmpl", s(
			"ReportResultToolName", "SummarizationToolName", "SummarizedContentPrefix",
			"Cwd", "Lang", "N", "ToolPlaceholder", "UserFiles",
		), []string{"<no value>"}},
	}
	failed := false
	for _, c := range checks {
		raw, err := os.ReadFile(c.name)
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", c.name, err)
			failed = true
			continue
		}
		booleans := []bool{false, true}
		if !strings.Contains(c.name, "pentester") {
			booleans = []bool{false}
		}
		for _, g := range booleans {
			vars := map[string]any{}
			for k, v := range c.vars {
				vars[k] = v
			}
			vars["N"] = 8000
			vars["GraphitiEnabled"] = g
			t, perr := template.New(c.name).Parse(string(raw))
			if perr != nil {
				fmt.Printf("[FAIL] %s (graphiti=%v) parse: %v\n", c.name, g, perr)
				failed = true
				continue
			}
			var buf strings.Builder
			if eerr := t.Execute(&buf, vars); eerr != nil {
				fmt.Printf("[FAIL] %s (graphiti=%v) execute: %v\n", c.name, g, eerr)
				failed = true
				continue
			}
			out := buf.String()
			bad := ""
			for _, f := range c.forbid {
				if strings.Contains(out, f) {
					bad = "contains unresolved token " + f
					failed = true
					break
				}
			}
			if bad == "" {
				fmt.Printf("[OK]   %s rendered (graphiti=%v, %d chars)\n", c.name, g, len(out))
			} else {
				fmt.Printf("[FAIL] %s (graphiti=%v): %s\n", c.name, g, bad)
			}
		}
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("ALL TEMPLATES OK")
}
