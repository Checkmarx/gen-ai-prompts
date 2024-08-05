package main

import (
	"flag"
	"fmt"
	"os"

	sastchat "github.com/checkmarxDev/ast-ai-prompts/sast_result_remediation"
)

const usage = `
Create an OpenAI prompt for SAST result remediation

Usage: prompt -s <sourcePath> -r <resultsFile> -ri <resultId>

Options:
    -s, --source <sourcePath>     Specify where the sources are located.
    -r, --results <resultsFile>   Specify the SAST results file to use. 
    -ri, --result-id <result-id>  Specify which result to use. 
    -h, --help                    Show help information.
`

func main() {

	var help bool
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
		fmt.Println("Results file is required")
		return
	}
	if resultId == "" {
		fmt.Println("Result ID is required")
		return
	}
	if sourcePath == "" {
		fmt.Println("Source path is required")
		return
	}

	results, err := sastchat.ReadResultsSAST(resultsFile)
	if err != nil {
		fmt.Printf("Error '%v' reading results file '%s': ", err, resultsFile)
		os.Exit(1)
	}
	result, err := sastchat.GetResultByID(results, resultId)
	if err != nil {
		fmt.Printf("Error '%v' getting result by ID '%s': ", err, resultId)
		os.Exit(1)
	}
	sources, err := sastchat.GetSourcesForResult(result, sourcePath)
	if err != nil {
		fmt.Printf("Error '%v' getting sources for result ID '%s': ", err, resultId)
		os.Exit(1)
	}

	system := sastchat.GetSystemPrompt()
	user, err := sastchat.CreateUserPrompt(result, sources)
	if err != nil {
		fmt.Printf("Error '%v' creating user prompt for result ID '%s': ", err, resultId)
		os.Exit(1)
	}

	fmt.Printf("system prompt: '%s'\n", system)
	fmt.Printf("user prompt: '%s'\n", user)
}
