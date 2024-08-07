package main

import (
	"flag"
	"fmt"
	"os"

	sastchat "github.com/CheckmarxDev/ast-ai-prompts/prompts/sast_result_remediation"
)

const (
	SastResult int = iota + 1
)

const (
	SastResultType string = "sast-result"
	promptTypes    string = "sast-result"
)

const usage = `
Create an OpenAI prompt for SAST result remediation

Usage: prompt [-p sast-result] -s <sourcePath> -r <resultsFile> -ri <resultId>

Options:
    -p, --prompt <promptType>     Specify the type of prompt to generate [` + promptTypes + `] (default: sast-result)
    -s, --source <sourcePath>     Specify where the sources are located.
    -r, --results <resultsFile>   Specify the SAST results file to use. 
    -ri, --result-id <result-id>  Specify which result to use. 
    -h, --help                    Show help information.
`

var sourcePath string = ""
var resultsFile string = ""
var resultId string = ""

func main() {

	help := false
	flag.BoolVar(&help, "help", false, "")
	flag.BoolVar(&help, "h", false, "")

	var promptType string
	flag.StringVar(&promptType, "p", "sast-result", "")
	flag.StringVar(&promptType, "prompt", "sast-result", "")

	flag.StringVar(&sourcePath, "s", "", "")
	flag.StringVar(&sourcePath, "source", "", "")

	flag.StringVar(&resultsFile, "r", "", "")
	flag.StringVar(&resultsFile, "results", "", "")

	flag.StringVar(&resultId, "ri", "", "")
	flag.StringVar(&resultId, "result-id", "", "")

	flag.Usage = func() {
		fmt.Print(usage)
		os.Exit(1)
	}

	flag.Parse()

	if help {
		flag.Usage()
	}

	if promptType != SastResultType {
		fmt.Printf("Invalid prompt type '%s'. Must be one of ['%s']\n", promptType, promptTypes)
		os.Exit(1)
	}

	buildPrompt(promptType)
}

func buildPrompt(promptType string) {

	switch promptType {
	case "sast-result":
		buildSastResultPrompt()
	}
}

func buildSastResultPrompt() {
	if resultsFile == "" && resultId == "" && sourcePath == "" {
		flag.Usage()
	}
	if resultsFile == "" {
		fmt.Println("Results file is required for SAST result prompt")
		os.Exit(1)
	}
	if resultId == "" {
		fmt.Println("Result ID is required for SAST result prompt")
		os.Exit(1)
	}
	if sourcePath == "" {
		fmt.Println("Source path is required for SAST result prompt")
		os.Exit(1)
	}

	system, user, err := sastchat.BuildPrompt(resultsFile, resultId, sourcePath)
	if err != nil {
		fmt.Printf("Error building SAST result prompt: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("SAST Result Remediation Prompt for result '%s' in results file '%s' with sources '%s'\n\n", resultId, resultsFile, sourcePath)
	fmt.Printf("System Prompt:\n\n%s\n\n", system)
	fmt.Printf("User Prompt:\n\n%s\n\n", user)
}
