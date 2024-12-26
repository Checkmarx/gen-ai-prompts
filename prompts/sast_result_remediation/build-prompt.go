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

	var prompt *SastResultPrompt = &SastResultPrompt{
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
	return pb.BuildPromptFromResult(result)
}

func (pb *PromptBuilder) BuildPromptsForResultsList(resultsListFile string) []*SastResultPrompt {
	var prompt *SastResultPrompt = &SastResultPrompt{
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
	results, err := GetResultsByList(scanResults.Results, resultsListFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error getting results from results list file '%s': '%v'", resultsListFile, err)
		return prompts
	}
	cleanSources := pb.GetSourcesForResults(results)
	return pb.CreatePromptsForResults(results, cleanSources, prompt)
}

func (pb *PromptBuilder) BuildPromptFromResult(result *Result) *SastResultPrompt {
	prompt := pb.initPrompt(result.Data.LanguageName, result.Data.QueryName)
	prompt.ResultId = result.ID
	prompt.Severity = result.Severity
	sources := pb.GetSourcesForResult(result)
	prompt.System = GetSystemPrompt()
	var err error
	prompt.User, err = pb.CreateUserPrompt(result, sources)
	if err != nil {
		prompt.Error = fmt.Errorf("error creating prompt for result ID '%s': '%v'", result.ID, err)
		return prompt
	}

	return prompt
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

func (pb *PromptBuilder) BuildPromptsFromResultsForLanguageAndQuery(results []*Result, language string, query string) []*SastResultPrompt {
	prompt := pb.initPrompt(language, query)
	var prompts []*SastResultPrompt
	prompts = append(prompts, prompt)

	results, err := GetResultsForLanguageAndQuery(results, language, query)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'\n", pb.ResultsFile, err)
		return prompts
	}
	cleanSources := pb.GetSourcesForResults(results)
	return pb.CreatePromptsForResults(results, cleanSources, prompt)
}

func (pb *PromptBuilder) initPrompt(language string, query string) *SastResultPrompt {
	return &SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		Language:    language,
		Query:       query,
		SourcePath:  pb.SourcePath,
	}
}
