package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	sastchat "github.com/Checkmarx/gen-ai-prompts/prompts/sast_result_remediation"
)

const (
	sastResult      string = "sast-result"
	sastResultNodes string = "sast-result-nodes"
	sastResultExtra string = "sast-result-extra"
	promptTypes     string = sastResult + ", " + sastResultNodes + ", " + sastResultExtra
)

const usage = `
Create an OpenAI prompt for SAST result remediation

Usage: prompt [-p ` + sastResult + `] -s <sourcePath> -r <resultsFile> [options]

Options:
    -p,  --prompt <promptType>    Specify the type of prompt to generate [` + promptTypes + `] (default: ` + sastResultNodes + `)
    -s,  --source <sourcePath>    Specify where the sources are located.
    -r,  --results <resultsFile>  Specify the SAST results file to use. 
    -ri, --result-id <result-id>  Specify which result to use.
    -rl, --result-list <listFile> result IDs file to remediate
    -q,  --query <language:query> Specify the query to use. Query must be in the format 'language:query'.
    -l,  --language <language>    Specify the language to use.
    -h,  --help                   Show help information.
`

var sourcePath string = ""
var resultsFile string = ""
var resultId string = ""
var resultsListFile string = ""
var query string = ""
var language string = ""
var nodeLinesOnly bool = false

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

	flag.StringVar(&resultsListFile, "rl", "", "")
	flag.StringVar(&resultsListFile, "result-list", "", "")

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

	if promptType != sastResult &&
		promptType != sastResultNodes {
		fmt.Printf("Invalid prompt type '%s'. Must be one of ['%s']\n", promptType, promptTypes)
		os.Exit(1)
	}

	buildPrompts(promptType)
}

func buildPrompts(promptType string) {

	switch promptType {
	case sastResult, sastResultNodes:
		buildSastResultPrompts(true)
	case sastResultExtra:
		buildSastResultPrompts(false)
	}
}

func buildSastResultPrompts(nodeLinesOnly bool) {
	if resultsFile == "" && resultId == "" && sourcePath == "" && resultsListFile == "" {
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

	pb := &sastchat.PromptBuilder{
		ResultsFile:   resultsFile,
		SourcePath:    sourcePath,
		NodeLinesOnly: nodeLinesOnly,
	}

	if resultId != "" {
		buildPromptForResult(pb, resultId)
	} else if resultsListFile != "" {
		buildPromptsForResultList(pb, resultsListFile)
	} else if query != "" {
		parts := strings.Split(query, ":")
		if len(parts) != 2 {
			fmt.Println("Query must be in the format 'language:query'")
			os.Exit(1)
		}
		language = parts[0]
		query = parts[1]
		buildPromptsForLanguageAndQuery(pb, language, query)
	} else if language != "" {
		buildPromptsForLanguageAndQuery(pb, language, "*")
	} else {
		buildPromptsForLanguageAndQuery(pb, "*", "*")
	}
}

func buildPromptsForLanguageAndQuery(pb *sastchat.PromptBuilder, language, query string) {
	var prompts []*sastchat.SastResultPrompt
	prompts = pb.BuildPromptsForLanguageAndQuery(language, query)
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

func buildPromptForResult(pb *sastchat.PromptBuilder, resultId string) {
	prompt := pb.BuildPromptForResultId(resultId)
	if prompt.Error != nil {
		fmt.Printf("Error building SAST result prompt for result ID '%s': %v\n", resultId, prompt.Error)
		os.Exit(1)
	}
	fmt.Printf("SAST Result Remediation Prompt for result ID '%s' with Language '%s' and Query '%s' in results file '%s' with sources '%s'\n\n",
		prompt.ResultId, prompt.Language, prompt.Query, prompt.ResultsFile, prompt.SourcePath)
	fmt.Printf("System Prompt:\n\n%s\n\n", prompt.System)
	fmt.Printf("User Prompt:\n\n%s\n\n", prompt.User)
}

func buildPromptsForResultList(pb *sastchat.PromptBuilder, resultsListFile string) {
	prompts := pb.BuildPromptsForResultsListFile(resultsListFile)
	for _, prompt := range prompts {
		if prompt.Error != nil {
			fmt.Printf("Error building SAST result prompt for result ID '%s': %v\n", prompt.ResultId, prompt.Error)
			continue
		}
		fmt.Printf("SAST Result Remediation Prompt for result ID '%s' from results list file '%s' in results file '%s' with sources '%s'\n\n",
			prompt.ResultId, resultsListFile, prompt.ResultsFile, prompt.SourcePath)
		fmt.Printf("System Prompt:\n\n%s\n\n", prompt.System)
		fmt.Printf("User Prompt:\n\n%s\n\n", prompt.User)
	}
}
