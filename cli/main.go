package main

import (
	"flag"
	"fmt"
	"os"

	sastchat "github.com/checkmarxDev/ast-ai-prompts/sast_result_remediation"
)

func main() {

	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Create an OpenAI prompt for SAST result remediation")
		return
	} else if len(args) != 3 {
		fmt.Println("Usage: cli <results.json> <result-id> <source-dir>")
		return
	}

	resultsFile := args[0]
	results, err := sastchat.ReadResultsSAST(resultsFile)
	if err != nil {
		fmt.Printf("Error '%v' reading results file '%s': ", err, resultsFile)
		os.Exit(1)
	}
	resultId := args[1]
	result, err := sastchat.GetResultByID(results, resultId)
	if err != nil {
		fmt.Printf("Error '%v' getting result by ID '%s': ", err, resultId)
		os.Exit(1)
	}
	sourceDir := args[2]
	sources, err := sastchat.GetSourcesForResult(result, sourceDir)
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
