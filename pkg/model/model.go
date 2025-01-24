package model

import "encoding/json"

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

type SourceAndError struct {
	Source []string
	Error  error
}

type ParsedResponse struct {
	Confidence   int
	Explanation  string
	Fix          string
	Introduction string
}
