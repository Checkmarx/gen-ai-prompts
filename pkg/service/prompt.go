package service

import "github.com/Checkmarx/gen-ai-prompts/pkg/model"

type Prompt interface {
	BuildPromptForResultId(resultId string) *model.SastResultPrompt
	BuildPromptsForResultsListFile(resultsListFile string) []*model.SastResultPrompt
	BuildPromptsForResults(results []*model.Result) []*model.SastResultPrompt
	BuildPromptForResult(result *model.Result) *model.SastResultPrompt
	BuildPromptsForLanguageAndQuery(language, query string) []*model.SastResultPrompt
	BuildPromptsForSeverity(severity string) []*model.SastResultPrompt
	BuildPromptsFromResultsForLanguageAndQuery(results []*model.Result, language string, query string) []*model.SastResultPrompt
	CreatePromptsForResults(results []*model.Result, cleanSources map[string]*model.SourceAndError, promptTemplate *model.SastResultPrompt) []*model.SastResultPrompt
	CreateUserPrompt(result *model.Result, sources map[string]*model.SourceAndError) (string, error)
}
