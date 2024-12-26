package sast_result_remediation

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type SourceAndError struct {
	Source []string
	Error  error
}

func (pb *PromptBuilder) GetSourcesForResults(results []*Result) map[string]*SourceAndError {
	sourceFilenames := make(map[string]error)
	for _, result := range results {
		getFilenamesForResult(result, sourceFilenames)
	}

	fileContents := make(map[string]*SourceAndError)
	for filename, err := range sourceFilenames {
		if err != nil {
			fileContents[filename] = &SourceAndError{Source: nil, Error: err}
			continue
		}
		lines, err := pb.GetFileContents(filename)
		if err != nil || lines == nil || len(lines) <= 1 {
			if err == nil {
				err = fmt.Errorf("file '%s' has irrelevant content", filename)
			}
			sourceFilenames[filename] = err
			fileContents[filename] = &SourceAndError{Source: nil, Error: err}
		} else {
			fileContents[filename] = &SourceAndError{Source: lines, Error: nil}
		}
	}

	return fileContents
}

func (pb *PromptBuilder) GetSourcesForResult(result *Result) map[string]*SourceAndError {
	results := []*Result{result}
	return pb.GetSourcesForResults(results)
}

func (pb *PromptBuilder) GetFileContents(filename string) ([]string, error) {
	sourceFilename := filepath.Join(pb.SourcePath, filename)
	file, err := os.Open(sourceFilename)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)
	var lines []string

	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if err != nil {
			if err == io.EOF {
				// Add the last line if it doesn't end with a newline
				if len(line) > 0 {
					lines = append(lines, line)
				}
				break
			}
			return nil, err
		}
		lines = append(lines, line)
	}

	err = file.Close()
	if err != nil {
		return lines, err
	}

	return lines, nil
}

func getFilenamesForResult(result *Result, sourceFilenames map[string]error) {
	for _, node := range result.Data.Nodes {
		sourceFilename := strings.ReplaceAll(node.FileName, "\\", "/")
		sourceFilenames[sourceFilename] = isResultRelevantForAnalysis(result, sourceFilename)
	}
}

func isResultRelevantForAnalysis(result *Result, filename string) error {
	var blacklistedExtensionsByLanguage = map[string][]string{
		"JavaScript": []string{".min.js", "-min.js"},
	}

	extensions, exists := blacklistedExtensionsByLanguage[result.Data.LanguageName]
	if !exists {
		return nil
	}
	for _, ext := range extensions {
		if strings.HasSuffix(filename, ext) {
			return fmt.Errorf("blacklisted extension: %s", ext)
		}
	}
	return nil
}
