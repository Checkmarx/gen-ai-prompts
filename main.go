package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	sastchat "github.com/Checkmarx/gen-ai-prompts/prompts/sast_result_remediation"
)

const (
	SastResultType string = "sast-result"
	promptTypes    string = "sast-result"
)

const usage = `
Create an OpenAI prompt for SAST result remediation

Usage: prompt [-p sast-result] -s <sourcePath> -r <resultsFile> [options]

Options:
    -p,  --prompt <promptType>    Specify the type of prompt to generate [` + promptTypes + `] (default: sast-result)
    -s,  --source <sourcePath>    Specify where the sources are located.
    -r,  --results <resultsFile>  Specify the SAST results file to use. 
    -ri, --result-id <result-id>  Specify which result to use.
    -q,  --query <language:query> Specify the query to use. Query must be in the format 'language:query'.
    -l,  --language <language>    Specify the language to use.
    -h,  --help                   Show help information.
`

var sourcePath string = ""
var resultsFile string = ""
var resultId string = ""
var query string = ""
var language string = ""

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

	flag.StringVar(&query, "q", "", "")
	flag.StringVar(&query, "query", "", "")

	flag.StringVar(&language, "l", "", "")
	flag.StringVar(&language, "language", "", "")

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

	buildPrompts(promptType)
}

func buildPrompts(promptType string) {

	switch promptType {
	case "sast-result":
		buildSastResultPrompts()
	}
}

func buildSastResultPrompts() {
	if resultsFile == "" && resultId == "" && sourcePath == "" {
		flag.Usage()
	}
	if resultsFile == "" {
		fmt.Println("Results file is required for SAST result prompt")
		os.Exit(1)
	}
	if sourcePath == "" {
		fmt.Println("Source path is required for SAST result prompt")
		os.Exit(1)
	}

	if resultId != "" {
		buildPromptForResult(resultsFile, resultId, sourcePath)
	} else if query != "" {
		parts := strings.Split(query, ":")
		if len(parts) != 2 {
			fmt.Println("Query must be in the format 'language:query'")
			os.Exit(1)
		}
		language = parts[0]
		query = parts[1]
		buildPromptsForLanguageAndQuery(resultsFile, language, query, sourcePath)
	} else if language != "" {
		buildPromptsForLanguageAndQuery(resultsFile, language, "*", sourcePath)
	} else {
		buildPromptsForLanguageAndQuery(resultsFile, "*", "*", sourcePath)
	}
}

func buildPromptsForLanguageAndQuery(resultsFile, language, query, sourcePath string) {
	var prompts []*sastchat.SastResultPrompt
	prompts = sastchat.BuildPromptsForLanguageAndQuery(resultsFile, language, query, sourcePath)
	for _, prompt := range prompts {
		if prompt.Error != nil {
			fmt.Printf("Error building SAST result prompt for result ID '%s': %v\n", prompt.ResultId, prompt.Error)
			continue
		}
		fmt.Printf("SAST Result Remediation Prompt for result ID '%s' with Language '%s' and Query '%s' in results file '%s' with sources '%s'\n\n",
			prompt.ResultId, prompt.Language, prompt.Query, prompt.ResultsFile, prompt.SourcePath)
		fmt.Printf("System Prompt:\n\n%s\n\n", prompt.System)
		fmt.Printf("User Prompt:\n\n%s\n\n", prompt.User)
	}
}

func buildPromptForResult(resultsFile, resultId, sourcePath string) {
	prompt := sastchat.BuildPromptForResultId(resultsFile, resultId, sourcePath)
	if prompt.Error != nil {
		fmt.Printf("Error building SAST result prompt for result ID '%s': %v\n", resultId, prompt.Error)
		os.Exit(1)
	}
	fmt.Printf("SAST Result Remediation Prompt for result ID '%s' with Language '%s' and Query '%s' in results file '%s' with sources '%s'\n\n",
		prompt.ResultId, prompt.Language, prompt.Query, prompt.ResultsFile, prompt.SourcePath)
	fmt.Printf("System Prompt:\n\n%s\n\n", prompt.System)
	fmt.Printf("User Prompt:\n\n%s\n\n", prompt.User)
}
