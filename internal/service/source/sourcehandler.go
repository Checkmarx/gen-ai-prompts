package source

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Checkmarx/gen-ai-prompts/pkg/model"
)

type SourceHandlerImpl struct {
	sourcePath string
}

func NewSourceHandlerImpl(sourcePath string) *SourceHandlerImpl {
	return &SourceHandlerImpl{sourcePath: sourcePath}
}

func (s *SourceHandlerImpl) GetSourcesForResults(results []*model.Result) map[string]*model.SourceAndError {
	sourceFilenames := make(map[string]error)
	for _, result := range results {
		s.getFilenamesForResult(result, sourceFilenames)
	}

	fileContents := make(map[string]*model.SourceAndError)
	for filename, err := range sourceFilenames {
		if err != nil {
			fileContents[filename] = &model.SourceAndError{Source: nil, Error: err}
			continue
		}
		lines, err := s.GetFileContents(filename)
		if err != nil || lines == nil || len(lines) <= 1 {
			if err == nil {
				err = fmt.Errorf("file '%s' has irrelevant content", filename)
			}
			sourceFilenames[filename] = err
			fileContents[filename] = &model.SourceAndError{Source: nil, Error: err}
		} else {
			fileContents[filename] = &model.SourceAndError{Source: lines, Error: nil}
		}
	}

	return fileContents
}

func (s *SourceHandlerImpl) GetSourcesForResult(result *model.Result) map[string]*model.SourceAndError {
	results := []*model.Result{result}
	return s.GetSourcesForResults(results)
}

func (s *SourceHandlerImpl) GetFileContents(filename string) ([]string, error) {
	sourceFilename := filepath.Join(s.sourcePath, filename)
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

func (s *SourceHandlerImpl) getFilenamesForResult(result *model.Result, sourceFilenames map[string]error) {
	for _, node := range result.Data.Nodes {
		sourceFilename := strings.ReplaceAll(node.FileName, "\\", "/")
		sourceFilenames[sourceFilename] = s.isResultRelevantForAnalysis(result, sourceFilename)
	}
}

func (s *SourceHandlerImpl) isResultRelevantForAnalysis(result *model.Result, filename string) error {
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
