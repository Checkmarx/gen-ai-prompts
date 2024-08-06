package main

import (
	"flag"
	"fmt"
	"os"

	sastchat "github.com/checkmarxDev/ast-ai-prompts/prompts/sast_result_remediation"
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

func buildPrompt(promptType string) {

	switch promptType {
	case "sast-result":
		buildSastResultPrompt()
	}

}

func buildSastResultPrompt() {
	help := false
	flag.BoolVar(&help, "help", false, "")
	flag.BoolVar(&help, "h", false, "")

	sourcePath := ""
	flag.StringVar(&sourcePath, "s", "", "")
	flag.StringVar(&sourcePath, "source", "", "")

	resultsFile := ""
	flag.StringVar(&resultsFile, "r", "", "")
	flag.StringVar(&resultsFile, "results", "", "")

	resultId := ""
	flag.StringVar(&resultId, "ri", "", "")
	flag.StringVar(&resultId, "result-id", "", "")

	flag.Usage = func() {
		fmt.Print(usage)
	}

	flag.Parse()

	if resultsFile == "" && resultId == "" && sourcePath == "" {
		help = true
	}

	if help {
		flag.Usage()
		os.Exit(1)
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

	fmt.Printf("System Prompt:\n%s\n", system)
	fmt.Printf("User Prompt:\n%s\n", user)
}
