package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type palette struct {
	enabled bool
}

func detectPalette(mode string, output io.Writer) palette {
	switch strings.ToLower(mode) {
	case "always":
		return palette{enabled: true}
	case "never":
		return palette{}
	}
	file, ok := output.(*os.File)
	if !ok {
		return palette{}
	}
	info, err := file.Stat()
	return palette{enabled: err == nil && info.Mode()&os.ModeCharDevice != 0}
}

func (p palette) wrap(code, value string) string {
	if !p.enabled {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func (p palette) bold(value string) string   { return p.wrap("1", value) }
func (p palette) blue(value string) string   { return p.wrap("94", value) }
func (p palette) cyan(value string) string   { return p.wrap("96", value) }
func (p palette) green(value string) string  { return p.wrap("92", value) }
func (p palette) red(value string) string    { return p.wrap("91", value) }
func (p palette) yellow(value string) string { return p.wrap("93", value) }
func (p palette) magenta(value string) string {
	return p.wrap("95", value)
}
func (p palette) dim(value string) string { return p.wrap("2", value) }

func (p palette) statusBlue(value string) string   { return p.bold(p.blue(value)) }
func (p palette) statusGreen(value string) string  { return p.bold(p.green(value)) }
func (p palette) statusYellow(value string) string { return p.bold(p.yellow(value)) }

func printBanner(output io.Writer, colors palette) {
	lines := []string{
		"\u2584\u2584                      \u2584\u2584\u2584  \u2584\u2584\u2584          \u2584\u2584",
		"\u2588\u2588                 \u2588\u2588   \u2588\u2588\u2588  \u2588\u2588\u2588          \u2588\u2588        \u2588\u2588",
		"\u2588\u2588\u2588\u2588\u2584 \u2584\u2588\u2588\u2588\u2584 \u2584\u2588\u2580\u2580\u2580 \u2580\u2588\u2588\u2580\u2580 \u2588\u2588\u2588  \u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2584 \u2584\u2588\u2588\u2588\u2588  \u2580\u2580\u2588\u2584 \u2580\u2588\u2588\u2580\u2580 \u2584\u2588\u2580\u2588\u2584 \u2588\u2588\u2588\u2588\u2584",
		"\u2588\u2588 \u2588\u2588 \u2588\u2588 \u2588\u2588 \u2580\u2588\u2588\u2588\u2584  \u2588\u2588   \u2588\u2588\u2588\u2584\u2584\u2588\u2588\u2588 \u2588\u2588 \u2588\u2588 \u2588\u2588 \u2588\u2588 \u2584\u2588\u2580\u2588\u2588  \u2588\u2588   \u2588\u2588\u2584\u2588\u2580 \u2588\u2588 \u2580\u2580",
		"\u2588\u2588 \u2588\u2588 \u2580\u2588\u2588\u2588\u2580 \u2584\u2584\u2584\u2588\u2580  \u2588\u2588   \u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2580 \u2588\u2588\u2588\u2588\u2580 \u2580\u2588\u2588\u2588\u2588 \u2580\u2588\u2584\u2588\u2588  \u2588\u2588   \u2580\u2588\u2584\u2584\u2584 \u2588\u2588",
		"                                 \u2588\u2588",
		"                                 \u2580\u2580",
	}
	fmt.Fprintln(output)
	for _, line := range lines {
		fmt.Fprintln(output, "  "+colors.blue(line))
	}
	fmt.Fprintf(output, "  %s%s%s%s%s\n\n",
		colors.dim("nxc /etc/hosts automatic sync | by: "),
		colors.bold(colors.red("shanksf")),
		colors.dim(" inspired by "),
		colors.bold(colors.red("eMVee")),
		colors.dim(""))
}
