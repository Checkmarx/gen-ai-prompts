package sast_result_remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Define the Go structs that match the JSON structure
type ResultPartial struct {
	Type                 string                 `json:"type"`
	Label                string                 `json:"label"`
	ID                   string                 `json:"id"`
	SimilarityID         string                 `json:"similarityId"`
	Status               string                 `json:"status"`
	State                string                 `json:"state"`
	Severity             string                 `json:"severity"`
	Created              string                 `json:"created"`
	FirstFoundAt         string                 `json:"firstFoundAt"`
	FoundAt              string                 `json:"foundAt"`
	FirstScanID          string                 `json:"firstScanId"`
	Description          string                 `json:"description"`
	DescriptionHTML      string                 `json:"descriptionHTML"`
	Data                 json.RawMessage        `json:"data"`
	Comments             map[string]interface{} `json:"comments"`
	VulnerabilityDetails json.RawMessage        `json:"vulnerabilityDetails"`
}
type Result struct {
	Type                 string                 `json:"type"`
	Label                string                 `json:"label"`
	ID                   string                 `json:"id"`
	SimilarityID         string                 `json:"similarityId"`
	Status               string                 `json:"status"`
	State                string                 `json:"state"`
	Severity             string                 `json:"severity"`
	Created              string                 `json:"created"`
	FirstFoundAt         string                 `json:"firstFoundAt"`
	FoundAt              string                 `json:"foundAt"`
	FirstScanID          string                 `json:"firstScanId"`
	Description          string                 `json:"description"`
	DescriptionHTML      string                 `json:"descriptionHTML"`
	Data                 Data                   `json:"data"`
	Comments             map[string]interface{} `json:"comments"`
	VulnerabilityDetails VulnerabilityDetails   `json:"vulnerabilityDetails"`
}

type Data struct {
	QueryID      uint64 `json:"queryId"`
	QueryName    string `json:"queryName"`
	Group        string `json:"group"`
	ResultHash   string `json:"resultHash"`
	LanguageName string `json:"languageName"`
	Nodes        []Node `json:"nodes"`
}

type Node struct {
	ID          string `json:"id"`
	Line        int    `json:"line"`
	Name        string `json:"name"`
	Column      int    `json:"column"`
	Length      int    `json:"length"`
	Method      string `json:"method"`
	NodeID      int    `json:"nodeID"`
	DomType     string `json:"domType"`
	FileName    string `json:"fileName"`
	FullName    string `json:"fullName"`
	TypeName    string `json:"typeName"`
	MethodLine  int    `json:"methodLine"`
	Definitions string `json:"definitions"`
}

type VulnerabilityDetails struct {
	CweID       int                    `json:"cweId"`
	Cvss        map[string]interface{} `json:"cvss"`
	Compliances []string               `json:"compliances"`
}

type ScanResultsPartial struct {
	Results    json.RawMessage `json:"results"`
	TotalCount int             `json:"totalCount"`
	ScanID     string          `json:"scanID"`
}

type ScanResults struct {
	Results    []*Result `json:"results"`
	TotalCount int       `json:"totalCount"`
	ScanID     string    `json:"scanID"`
}

func ReadResultsSAST(filename string) (*ScanResults, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON data into the ScanResults struct
	var scanResultsPartial ScanResultsPartial
	if err := json.Unmarshal(bytes, &scanResultsPartial); err != nil {
		return nil, err
	}

	var results []*Result
	var resultsPartial []*ResultPartial
	if err := json.Unmarshal(scanResultsPartial.Results, &resultsPartial); err != nil {
		return nil, err
	}

	for _, resultPartial := range resultsPartial {
		if resultPartial.Type != "sast" {
			continue
		}
		var data Data
		if err := json.Unmarshal(resultPartial.Data, &data); err != nil {
			return nil, err
		}
		var vulnerabilityDetails VulnerabilityDetails
		if err := json.Unmarshal(resultPartial.VulnerabilityDetails, &vulnerabilityDetails); err != nil {
			return nil, err
		}

		result := &Result{resultPartial.Type,
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
	scanResults := ScanResults{results, scanResultsPartial.TotalCount, scanResultsPartial.ScanID}
	return &scanResults, nil
}

func GetResultByID(results []*Result, resultID string) (*Result, error) {
	for _, result := range results {
		if result.ID == resultID {
			return result, nil
		}
	}
	return &Result{}, fmt.Errorf("result ID %s not found", resultID)
}

func GetResultsByList(results []*Result, resultsListFile string) ([]*Result, error) {
	var resultsByList []*Result

	resultIds, err := ReadResultsList(resultsListFile)
	if err != nil {
		return resultsByList, fmt.Errorf("error reading results list file '%s': '%v'", resultsListFile, err)
	}

	for _, resultId := range resultIds {
		result, err := GetResultByID(results, resultId)
		if err != nil {
			return nil, err
		}
		resultsByList = append(resultsByList, result)
	}
	return resultsByList, nil
}

func GetResultsForLanguageAndQuery(results []*Result, language, query string) ([]*Result, error) {
	var resultsForQuery []*Result
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

func ReadResultsList(listFile string) ([]string, error) {
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
