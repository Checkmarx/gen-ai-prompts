package scanresults

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Checkmarx/gen-ai-prompts/pkg/model"
)

type SastResultImp struct {
}

func NewSastResultImpl() *SastResultImp {
	return &SastResultImp{}
}

func (s *SastResultImp) ReadResultsSAST(filename string) (*model.ScanResults, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON data into the ScanResults struct
	var scanResultsPartial model.ScanResultsPartial
	if err := json.Unmarshal(bytes, &scanResultsPartial); err != nil {
		return nil, err
	}

	var results []*model.Result
	var resultsPartial []*model.ResultPartial
	if err := json.Unmarshal(scanResultsPartial.Results, &resultsPartial); err != nil {
		return nil, err
	}

	for _, resultPartial := range resultsPartial {
		if resultPartial.Type != "sast" {
			continue
		}
		var data model.Data
		if err := json.Unmarshal(resultPartial.Data, &data); err != nil {
			return nil, err
		}
		var vulnerabilityDetails model.VulnerabilityDetails
		if err := json.Unmarshal(resultPartial.VulnerabilityDetails, &vulnerabilityDetails); err != nil {
			return nil, err
		}

		result := &model.Result{resultPartial.Type,
			resultPartial.Label,
			resultPartial.ID,
			resultPartial.SimilarityID,
			resultPartial.Status,
			resultPartial.State,
			resultPartial.Severity,
			resultPartial.Created,
			resultPartial.FirstFoundAt,
			resultPartial.FoundAt,
			resultPartial.FirstScanID,
			resultPartial.Description,
			resultPartial.DescriptionHTML,
			data,
			resultPartial.Comments,
			vulnerabilityDetails}
		results = append(results, result)
	}
	scanResults := model.ScanResults{results, scanResultsPartial.TotalCount, scanResultsPartial.ScanID}
	return &scanResults, nil
}

func (s *SastResultImp) GetResultByID(results []*model.Result, resultID string) (*model.Result, error) {
	for _, result := range results {
		if result.ID == resultID {
			return result, nil
		}
	}
	return nil, fmt.Errorf("result ID %s not found", resultID)
}

func (s *SastResultImp) GetResultsByListFile(results []*model.Result, resultsListFile string) ([]*model.Result, error) {
	resultIds, err := s.ReadResultsList(resultsListFile)
	if err != nil {
		return nil, fmt.Errorf("error reading results list file '%s': '%v'", resultsListFile, err)
	}

	return s.GetResultsByList(results, resultIds)
}

func (s *SastResultImp) GetResultsByList(results []*model.Result, resultIds []string) ([]*model.Result, error) {
	var resultsByList []*model.Result
	for _, resultId := range resultIds {
		result, err := s.GetResultByID(results, resultId)
		if err != nil {
			return nil, err
		}
		resultsByList = append(resultsByList, result)
	}
	return resultsByList, nil
}

func (s *SastResultImp) GetResultsBySeverity(results []*model.Result, severity string) ([]*model.Result, error) {
	var resultsBySeverity []*model.Result
	for _, result := range results {
		if strings.EqualFold(result.Severity, severity) {
			resultsBySeverity = append(resultsBySeverity, result)
		}
	}
	if len(resultsBySeverity) == 0 {
		return nil, fmt.Errorf("no results found for severity '%s'", severity)
	}
	return resultsBySeverity, nil
}

func (s *SastResultImp) GetResultsForLanguageAndQuery(results []*model.Result, language, query string) ([]*model.Result, error) {
	var resultsForQuery []*model.Result
	for _, result := range results {
		if (language == "*" || strings.EqualFold(result.Data.LanguageName, language)) &&
			(query == "*" || strings.EqualFold(result.Data.QueryName, query)) {
			resultsForQuery = append(resultsForQuery, result)
		}
	}
	if len(resultsForQuery) == 0 {
		return resultsForQuery, fmt.Errorf("no results found for language '%s' and query '%s'", language, query)
	}
	return resultsForQuery, nil
}

func (s *SastResultImp) ReadResultsList(listFile string) ([]string, error) {
	content, err := os.ReadFile(listFile)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var results []string
	for _, line := range lines {
		if line != "" {
			results = append(results, strings.Trim(line, " "))
		}
	}
	return results, nil
}
