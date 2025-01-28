package source

import (
	"github.com/Checkmarx/gen-ai-prompts/pkg/model"
)

type SourceHandler interface {
	GetSourcesForResults(results []*model.Result) map[string]*model.SourceAndError
	GetSourcesForResult(result *model.Result) map[string]*model.SourceAndError
	GetFileContents(filename string) ([]string, error)
}
