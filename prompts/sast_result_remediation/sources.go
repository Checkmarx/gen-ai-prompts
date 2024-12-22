package sast_result_remediation

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func (pb *PromptBuilder) GetSourcesForResults(results []*Result) (map[string][]string, error) {
	sourceFilenames := make(map[string]bool)
	for _, result := range results {
		getFilenamesForResult(result, sourceFilenames)
	}

	fileContents := make(map[string][]string)
	for filename, load := range sourceFilenames {
		if !load {
			fileContents[filename] = nil
			continue
		}
		lines, err := pb.GetFileContents(filename)
		if err != nil || lines == nil || len(lines) <= 1 {
			sourceFilenames[filename] = false
			fileContents[filename] = nil
		} else {
			fileContents[filename] = lines
		}
	}

	return fileContents, nil
}

func (pb *PromptBuilder) GetSourcesForResult(result *Result) (map[string][]string, error) {
	var results []*Result = []*Result{result}
	return pb.GetSourcesForResults(results)
}

func (pb *PromptBuilder) GetFileContents(filename string) ([]string, error) {
	sourceFilename := filepath.Join(pb.SourcePath, filename)
	file, err := os.Open(sourceFilename)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	err = file.Close()
	if err != nil {
		return nil, err
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, err
}

func getFilenamesForResult(result *Result, sourceFilenames map[string]bool) {
	for _, node := range result.Data.Nodes {
		sourceFilename := strings.ReplaceAll(node.FileName, "\\", "/")
		sourceFilenames[sourceFilename] = isResultRelevantForAnalysis(result, sourceFilename)
	}
}

func isResultRelevantForAnalysis(result *Result, filename string) bool {
	var blacklistedExtensionsByLanguage = map[string][]string{
		"JavaScript": []string{".min.js", "-min.js"},
	}

	extensions, exists := blacklistedExtensionsByLanguage[result.Data.LanguageName]
	if !exists {
		return true
	}
	for _, ext := range extensions {
		if strings.HasSuffix(filename, ext) {
			return false
		}
	}
	return true
}
