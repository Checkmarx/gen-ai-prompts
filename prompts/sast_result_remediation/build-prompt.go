package sast_result_remediation

import (
	"fmt"
)

type SastResultPrompt struct {
	ResultsFile string
	Language    string
	Query       string
	ResultId    string
	SourcePath  string
	System      string
	User        string
	Error       error
}

func BuildPrompt(resultsFile string, resultId string, sourcePath string) (system, user string, err error) {
	prompt := BuildPromptForResultId(resultsFile, resultId, sourcePath)
	return prompt.System, prompt.User, prompt.Error
}

func BuildPromptForResultId(resultsFile string, resultId string, sourcePath string) *SastResultPrompt {

	var prompt *SastResultPrompt = &SastResultPrompt{
		ResultsFile: resultsFile,
		ResultId:    resultId,
		SourcePath:  sourcePath,
	}

	results, err := ReadResultsSAST(resultsFile)
	if err != nil {
		prompt.Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", resultsFile, err)
		return prompt
	}
	result, err := GetResultByID(results.Results, resultId)
	if err != nil {
		prompt.Error = fmt.Errorf("error getting result for result ID '%s': '%v'", resultId, err)
		return prompt
	}
	prompt.Language = result.Data.LanguageName
	prompt.Query = result.Data.QueryName
	sources, err := GetSourcesForResult(result, sourcePath)
	if err != nil {
		prompt.Error = fmt.Errorf("error getting sources for result ID '%s': '%v'", resultId, err)
		return prompt
	}

	prompt.System = GetSystemPrompt()
	prompt.User, err = CreateUserPrompt(result, sources)
	if err != nil {
		prompt.Error = fmt.Errorf("error creating prompt for result ID '%s': '%v'", resultId, err)
		return prompt
	}

	return prompt
}

func BuildPromptsForLanguageAndQuery(resultsFile, language, query, sourcePath string) []*SastResultPrompt {
	prompt := initPrompts(resultsFile, language, query, sourcePath)
	var prompts []*SastResultPrompt
	prompts = append(prompts, prompt)

	scanResults, err := ReadResultsSAST(resultsFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", resultsFile, err)
		return prompts
	}
	return BuildPromptsFromResultsForLanguageAndQuery(scanResults.Results, language, query, sourcePath, resultsFile)
}

func BuildPromptsFromResultsForLanguageAndQuery(results []*Result, language string, query string, sourcePath string, resultsFile string) []*SastResultPrompt {
	prompt := initPrompts(resultsFile, language, query, sourcePath)
	var prompts []*SastResultPrompt
	prompts = append(prompts, prompt)

	results, err := GetResultsForLanguageAndQuery(results, language, query)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'\n", resultsFile, err)
		return prompts
	}
	sources, err := GetSourcesForResults(results, sourcePath)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error getting sources for language '%s' and query '%s': '%v'", language, query, err)
		return prompts
	}

	return CreatePromptsForResults(results, sources, prompt)
}

func initPrompts(resultsFile string, language string, query string, sourcePath string) *SastResultPrompt {
	return &SastResultPrompt{
		ResultsFile: resultsFile,
		Language:    language,
		Query:       query,
		SourcePath:  sourcePath,
	}
}
