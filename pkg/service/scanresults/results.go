package scanresults

import "github.com/Checkmarx/gen-ai-prompts/pkg/model"

type SASTResults interface {
	ReadResultsSAST(filename string) (*model.ScanResults, error)
	GetResultByID(results []*model.Result, resultID string) (*model.Result, error)
	GetResultsByListFile(results []*model.Result, resultsListFile string) ([]*model.Result, error)
	GetResultsByList(results []*model.Result, resultIds []string) ([]*model.Result, error)
	GetResultsBySeverity(results []*model.Result, severity string) ([]*model.Result, error)
	GetResultsForLanguageAndQuery(results []*model.Result, language, query string) ([]*model.Result, error)
	ReadResultsList(listFile string) ([]string, error)
}
