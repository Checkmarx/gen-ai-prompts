package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	SastResult int = iota + 1
)

const (
	SastResultType string = "sast-result"
	promptTypes    string = "sast-result"
)

func main() {

	var help bool
	flag.BoolVar(&help, "help", false, "")
	flag.BoolVar(&help, "h", false, "")

	var promptType string
	flag.StringVar(&promptType, "p", "sast-result", "")
	flag.StringVar(&promptType, "prompt", "sast-result", "")

	flag.Parse()

	if promptType != SastResultType {
		fmt.Printf("Invalid prompt type '%s'. Must be one of ['%s']\n", promptType, promptTypes)
		os.Exit(1)
	}

	buildPrompt(promptType)
}
