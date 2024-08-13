package sast_result_remediation

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func GetSourcesForResults(results []*Result, sourceDir string) (map[string][]string, error) {
	sourceFilenames := make(map[string]bool)
	for _, result := range results {
		getFilenamesForResult(result, sourceFilenames)
	}

	fileContents, err := GetFileContents(sourceFilenames, sourceDir)
	if err != nil {
		return nil, err
	}

	return fileContents, nil
}

func GetSourcesForResult(result *Result, sourceDir string) (map[string][]string, error) {
	var results []*Result = []*Result{result}
	return GetSourcesForResults(results, sourceDir)
}

func GetFileContents(filenames map[string]bool, sourceDir string) (map[string][]string, error) {
	fileContents := make(map[string][]string)

	for filename, load := range filenames {
		if !load {
			fileContents[filename] = nil
			continue
		}
		sourceFilename := filepath.Join(sourceDir, filename)
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

		fileContents[filename] = lines
	}

	return fileContents, nil
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
