package sast_result_remediation

import (
	"fmt"
)

type SastResultPrompt struct {
	ResultsFile string
	Language    string
	Query       string
	Severity    string
	ResultId    string
	SourcePath  string
	System      string
	User        string
	Error       error
}

type PromptBuilder struct {
	ResultsFile   string
	SourcePath    string
	NodeLinesOnly bool
}

func BuildPrompt(resultsFile string, resultId string, sourcePath string) (system, user string, err error) {
	pb := &PromptBuilder{
		ResultsFile:   resultsFile,
		SourcePath:    sourcePath,
		NodeLinesOnly: true,
	}
	prompt := pb.BuildPromptForResultId(resultId)
	return prompt.System, prompt.User, prompt.Error
}

func (pb *PromptBuilder) BuildPromptForResultId(resultId string) *SastResultPrompt {

	var prompt = &SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		ResultId:    resultId,
		SourcePath:  pb.SourcePath,
	}

	results, err := ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompt.Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompt
	}
	result, err := GetResultByID(results.Results, resultId)
	if err != nil {
		prompt.Error = fmt.Errorf("error getting result for result ID '%s': '%v'", resultId, err)
		return prompt
	}
	return pb.BuildPromptForResult(result)
}

func (pb *PromptBuilder) BuildPromptsForResultsListFile(resultsListFile string) []*SastResultPrompt {
	var prompt = &SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		SourcePath:  pb.SourcePath,
	}
	var prompts []*SastResultPrompt
	prompts = append(prompts, prompt)

	scanResults, err := ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompts
	}
	// read the resultsListFile
	results, err := GetResultsByListFile(scanResults.Results, resultsListFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error getting results from results list file '%s': '%v'", resultsListFile, err)
		return prompts
	}
	return pb.BuildPromptsForResults(results)
}

func (pb *PromptBuilder) BuildPromptsForResults(results []*Result) []*SastResultPrompt {
	var prompt = &SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		SourcePath:  pb.SourcePath,
	}
	sources := pb.GetSourcesForResults(results)
	return pb.CreatePromptsForResults(results, sources, prompt)
}

func (pb *PromptBuilder) BuildPromptForResult(result *Result) *SastResultPrompt {
	results := []*Result{result}
	return pb.BuildPromptsForResults(results)[0]
}

func (pb *PromptBuilder) BuildPromptsForLanguageAndQuery(language, query string) []*SastResultPrompt {
	prompt := pb.initPrompt(language, query)
	var prompts []*SastResultPrompt
	prompts = append(prompts, prompt)

	scanResults, err := ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompts
	}
	return pb.BuildPromptsFromResultsForLanguageAndQuery(scanResults.Results, language, query)
}

func (pb *PromptBuilder) BuildPromptsForSeverity(severity string) []*SastResultPrompt {
	prompt := &SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		Severity:    severity,
		SourcePath:  pb.SourcePath,
	}

	var prompts []*SastResultPrompt
	prompts = append(prompts, prompt)

	scanResults, err := ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompts
	}
	results, err := GetResultsBySeverity(scanResults.Results, severity)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error getting results for severity '%s': '%v'", severity, err)
		return prompts
	}
	return pb.BuildPromptsForResults(results)
}

func (pb *PromptBuilder) BuildPromptsFromResultsForLanguageAndQuery(results []*Result, language string, query string) []*SastResultPrompt {
	prompt := pb.initPrompt(language, query)
	var prompts []*SastResultPrompt
	prompts = append(prompts, prompt)

	results, err := GetResultsForLanguageAndQuery(results, language, query)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'\n", pb.ResultsFile, err)
		return prompts
	}
	return pb.BuildPromptsForResults(results)
}

func (pb *PromptBuilder) initPrompt(language string, query string) *SastResultPrompt {
	return &SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		Language:    language,
		Query:       query,
		SourcePath:  pb.SourcePath,
	}
}
