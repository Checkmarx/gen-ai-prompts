package prompt

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Checkmarx/gen-ai-prompts/pkg/model"
	"github.com/Checkmarx/gen-ai-prompts/pkg/service/scanresults"
	"github.com/Checkmarx/gen-ai-prompts/pkg/service/source"
	"github.com/Checkmarx/gen-ai-prompts/pkg/utils"
)

type PromptBuilder struct {
	ResultsFile   string
	SourcePath    string
	NodeLinesOnly bool
	sastResults   scanresults.SASTResults
	sourceHandler source.SourceHandler
}

func NewPromptBuilder(sr scanresults.SASTResults, sourceHandler source.SourceHandler, resultsFile, sourcePath string, nodeLinesOnly bool) *PromptBuilder {
	return &PromptBuilder{
		sastResults:   sr,
		sourceHandler: sourceHandler,
		ResultsFile:   resultsFile,
		SourcePath:    sourcePath,
		NodeLinesOnly: nodeLinesOnly,
	}
}

func (pb *PromptBuilder) BuildPromptForResultId(resultId string) *model.SastResultPrompt {

	var prompt = &model.SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		ResultId:    resultId,
		SourcePath:  pb.SourcePath,
	}

	results, err := pb.sastResults.ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompt.Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompt
	}
	result, err := pb.sastResults.GetResultByID(results.Results, resultId)
	if err != nil {
		prompt.Error = fmt.Errorf("error getting result for result ID '%s': '%v'", resultId, err)
		return prompt
	}
	return pb.BuildPromptForResult(result)
}

func (pb *PromptBuilder) BuildPromptsForResultsListFile(resultsListFile string) []*model.SastResultPrompt {
	var prompt = &model.SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		SourcePath:  pb.SourcePath,
	}
	var prompts []*model.SastResultPrompt
	prompts = append(prompts, prompt)

	scanResults, err := pb.sastResults.ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompts
	}
	// read the resultsListFile
	results, err := pb.sastResults.GetResultsByListFile(scanResults.Results, resultsListFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error getting results from results list file '%s': '%v'", resultsListFile, err)
		return prompts
	}
	return pb.BuildPromptsForResults(results)
}

func (pb *PromptBuilder) BuildPromptsForResults(results []*model.Result) []*model.SastResultPrompt {
	var prompt = &model.SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		SourcePath:  pb.SourcePath,
	}
	sources := pb.sourceHandler.GetSourcesForResults(results)
	return pb.CreatePromptsForResults(results, sources, prompt)
}

func (pb *PromptBuilder) BuildPromptForResult(result *model.Result) *model.SastResultPrompt {
	results := []*model.Result{result}
	return pb.BuildPromptsForResults(results)[0]
}

func (pb *PromptBuilder) BuildPromptsForLanguageAndQuery(language, query string) []*model.SastResultPrompt {
	prompt := pb.initPrompt(language, query)
	var prompts []*model.SastResultPrompt
	prompts = append(prompts, prompt)

	scanResults, err := pb.sastResults.ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompts
	}
	return pb.BuildPromptsFromResultsForLanguageAndQuery(scanResults.Results, language, query)
}

func (pb *PromptBuilder) BuildPromptsForSeverity(severity string) []*model.SastResultPrompt {
	prompt := &model.SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		Severity:    severity,
		SourcePath:  pb.SourcePath,
	}

	var prompts []*model.SastResultPrompt
	prompts = append(prompts, prompt)

	scanResults, err := pb.sastResults.ReadResultsSAST(pb.ResultsFile)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'", pb.ResultsFile, err)
		return prompts
	}
	results, err := pb.sastResults.GetResultsBySeverity(scanResults.Results, severity)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error getting results for severity '%s': '%v'", severity, err)
		return prompts
	}
	return pb.BuildPromptsForResults(results)
}

func (pb *PromptBuilder) BuildPromptsFromResultsForLanguageAndQuery(results []*model.Result, language string, query string) []*model.SastResultPrompt {
	prompt := pb.initPrompt(language, query)
	var prompts []*model.SastResultPrompt
	prompts = append(prompts, prompt)

	results, err := pb.sastResults.GetResultsForLanguageAndQuery(results, language, query)
	if err != nil {
		prompts[0].Error = fmt.Errorf("error reading and parsing SAST results file '%s': '%v'\n", pb.ResultsFile, err)
		return prompts
	}
	return pb.BuildPromptsForResults(results)
}

func (pb *PromptBuilder) initPrompt(language string, query string) *model.SastResultPrompt {
	return &model.SastResultPrompt{
		ResultsFile: pb.ResultsFile,
		Language:    language,
		Query:       query,
		SourcePath:  pb.SourcePath,
	}
}

func (pb *PromptBuilder) CreatePromptsForResults(results []*model.Result, cleanSources map[string]*model.SourceAndError, promptTemplate *model.SastResultPrompt) []*model.SastResultPrompt {
	var prompts []*model.SastResultPrompt
	for _, result := range results {
		prompt := &model.SastResultPrompt{
			ResultsFile: promptTemplate.ResultsFile,
			SourcePath:  promptTemplate.SourcePath,
			Language:    result.Data.LanguageName,
			Query:       result.Data.QueryName,
			ResultId:    result.ID,
			Severity:    result.Severity,
		}
		prompt.System = GetSystemPrompt()
		sources := copyCleanSources(cleanSources)
		prompt.User, prompt.Error = pb.CreateUserPrompt(result, sources)
		prompts = append(prompts, prompt)
	}
	return prompts
}

func (pb *PromptBuilder) CreateUserPrompt(result *model.Result, sources map[string]*model.SourceAndError) (string, error) {
	var promptSource string
	var err error
	if pb.NodeLinesOnly {
		promptSource, err = createSourceForPromptWithNodeLinesOnly(result, sources)
		if err != nil {
			return "", err
		}
	} else {
		promptSource, err = pb.createSourceForPrompt(result, sources)
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf(utils.UserPromptTemplate, result.Data.QueryName, result.VulnerabilityDetails.CweID, result.Data.LanguageName, promptSource), nil
}

// createSourceForPrompt creates the comment-annotated source snippet for the SAST prompt.
// It iterates over the nodes in the result, collects the source lines from the beginning of the method to the node line,
// and annotates the lines with the node information. Whenever a new method is encountered, it fetches the method lines.
func (pb *PromptBuilder) createSourceForPrompt(result *model.Result, sources map[string]*model.SourceAndError) (string, error) {
	var sourcePrompt []string
	// methodsInPrompt collects the annotated source lines of all the methods
	// the key is 'method-index:method-filename:method-name'
	methodsInPrompt := make(map[string][]string)
	type IndexAndLine struct {
		Index int
		Line  int
	}
	// methods map holds the index of a method (starting from 0) and the line where it starts
	// the key is 'method-filename:method-name'
	methods := make(map[string]*IndexAndLine)
	methodCount := 0
	// methodLines holds the source lines of the current method
	var methodLines []string
	var methodIndexStr string
	for i := range result.Data.Nodes {
		node := result.Data.Nodes[i]
		sourceFilename := strings.ReplaceAll(node.FileName, "\\", "/")
		methodSpec := sourceFilename + ":" + node.Method + ":" + strconv.Itoa(node.MethodLine)
		methodIndex, exists := methods[methodSpec]
		if !exists { // first time this method is encountered in the result
			m, err := pb.GetMethodByMethodLine(sourceFilename, sources[sourceFilename], node.MethodLine, node.Line, false)
			if err != nil {
				e := fmt.Errorf("error getting method '%s': '%v'", node.Method, err)
				return "", fmt.Errorf(utils.ErrMsg, result.ID, e)
			}
			methodLines = m
			methods[methodSpec] = &IndexAndLine{Index: methodCount, Line: node.MethodLine}
			methodIndex = methods[methodSpec]
			methodIndexStr = fmt.Sprintf("%03d", methodIndex.Index)
			methodCount++
		} else {
			methodIndexStr = fmt.Sprintf("%03d", methodIndex.Index)
			methodLines = methodsInPrompt[methodIndexStr+":"+methodSpec]
			if len(methodLines) < node.Line-methodIndex.Line+1 { // need to add more lines to the method
				m, err := pb.GetMethodByMethodLine(sourceFilename, sources[sourceFilename], methodIndex.Line, node.Line, true)
				if err != nil {
					e := fmt.Errorf("error getting method '%s': '%v'", node.Method, err)
					return "", fmt.Errorf(utils.ErrMsg, result.ID, e)

				}
				methodLines = m
			}
		}

		lineInMethod := node.Line - methodIndex.Line
		// adjust in case the node.Line is before node.MethodLine
		if lineInMethod < 0 {
			lineInMethod = 0
		}
		var edge string
		if i == 0 {
			edge = " (input)"
		} else if i == len(result.Data.Nodes)-1 {
			edge = " (output)"
		} else {
			edge = ""
		}

		// change UnknownReference to something more informational like VariableReference or TypeNameReference
		nodeType := node.DomType
		if node.DomType == "UnknownReference" {
			if node.TypeName == "" {
				nodeType = "VariableReference"
			} else {
				nodeType = node.TypeName + "Reference"
			}
		}
		methodLines[lineInMethod] += fmt.Sprintf("//SAST Node #%d%s: %s (%s)", i, edge, node.Name, nodeType)
		methodsInPrompt[methodIndexStr+":"+methodSpec] = methodLines
	}

	var methodKeys []string
	for k := range methodsInPrompt {
		methodKeys = append(methodKeys, k)
	}
	sort.Strings(methodKeys)

	for _, methodKey := range methodKeys {
		methodLines := methodsInPrompt[methodKey]
		methodLines = append(methodLines, "// method continues ...")
		sourcePrompt = append(sourcePrompt, methodLines...)
	}

	return strings.Join(sourcePrompt, "\n"), nil
}

func (pb *PromptBuilder) GetMethodByMethodLine(filename string, source *model.SourceAndError, methodLineNumber, nodeLineNumber int, tagged bool) ([]string, error) {
	if source.Error != nil {
		return nil, fmt.Errorf("error reading source '%s': %v", filename, source.Error)
	}
	lines := source.Source
	if lines == nil {
		return nil, fmt.Errorf("source '%s' is irrelevant for analysis", filename)
	}
	if methodLineNumber < 1 || methodLineNumber > len(lines) {
		return nil, fmt.Errorf("method line number %d is out of range", methodLineNumber)
	}

	if nodeLineNumber < 1 || nodeLineNumber > len(lines) {
		return nil, fmt.Errorf("node line number %d is out of range", nodeLineNumber)
	}

	// Sometimes the method includes attributes or annotations that are not part of the method declaration
	// limit these to 5 lines difference
	if nodeLineNumber < methodLineNumber && methodLineNumber-nodeLineNumber > 5 {
		return nil, fmt.Errorf("node line number %d is less than method line number %d", nodeLineNumber, methodLineNumber)
	}

	// Compute startIndex and numberOfLines
	var startIndex int
	var numberOfLines int
	if nodeLineNumber < methodLineNumber { // in case the node is before the method
		startIndex = nodeLineNumber - 1 // adjust line number to 0-based index for slice access
		numberOfLines = methodLineNumber - nodeLineNumber + 1
	} else {
		startIndex = methodLineNumber - 1
		numberOfLines = nodeLineNumber - methodLineNumber + 1
	}
	methodLines := lines[startIndex : startIndex+numberOfLines]
	if !tagged {
		methodLines[0] += fmt.Sprintf("//FILE: %s:%d", filename, methodLineNumber)
	}
	return methodLines, nil
}

func (pb *PromptBuilder) ParseResponse(response string) (*model.ParsedResponse, error) {
	parsedResponse := &model.ParsedResponse{}
	c, i := findElement(response, utils.Confidence)
	if i == -1 {
		return parsedResponse, fmt.Errorf("confidence not found in response")
	}
	parsedResponse.Introduction = response[:i]
	e, j := findElement(response, utils.Explanation)
	if j == -1 {
		return parsedResponse, fmt.Errorf("explanation not found in response")
	}
	confidenceText := response[i+len(c) : j]
	f, k := findElement(response, utils.Fix)
	if k == -1 {
		return parsedResponse, fmt.Errorf("fix not found in response")
	}
	parsedResponse.Explanation = response[j+len(e) : k]
	parsedResponse.Fix = response[k+len(f):]
	confidenceDigits := getDigits(confidenceText)
	_, err := fmt.Sscanf(confidenceDigits, "%d", &parsedResponse.Confidence)
	if err != nil {
		return parsedResponse, fmt.Errorf("error converting confidence text to integer value: %v", err)
	}
	return parsedResponse, nil
}

func (pb *PromptBuilder) AddDescriptionForIdentifier(responseContent []string) []string {
	identifiersDescription := map[string]string{
		utils.BoldConfidence:  utils.ConfidenceDescription,
		utils.BoldExplanation: utils.ExplanationDescription,
		utils.BoldFix:         utils.FixDescription,
	}
	if len(responseContent) > 0 {
		for i := 0; i < len(responseContent); i++ {
			for identifier, description := range identifiersDescription {
				responseContent[i] = replaceIdentifierTitleIfNeeded(responseContent[i], identifier, description)
			}
		}
	}
	return responseContent
}

func GetSystemPrompt() string {
	return utils.SystemPrompt
}

func copyCleanSources(sources map[string]*model.SourceAndError) map[string]*model.SourceAndError {
	cleanSources := make(map[string]*model.SourceAndError)
	for k, v := range sources {
		source := make([]string, len(v.Source))
		copy(source, v.Source)
		cleanSources[k] = &model.SourceAndError{Source: source, Error: v.Error}
	}
	return cleanSources
}

// createSourceForPromptWithNodeLinesOnly creates the comment-annotated source snippet for the SAST prompt.
// It iterates over the nodes in the result and collects the source lines from the nodes and the method lines.
// It annotates the lines with the node information.
func createSourceForPromptWithNodeLinesOnly(result *model.Result, sources map[string]*model.SourceAndError) (string, error) {
	type NodeLine struct {
		Index int
		Line  int
	}
	type MethodSpec struct {
		Filename string
		Name     string
		Line     int
	}
	nodesInMethods := make(map[MethodSpec][]*NodeLine)
	var methods []MethodSpec
	var sourcePrompt []string
	for i, node := range result.Data.Nodes {
		sourceFilename := strings.ReplaceAll(node.FileName, "\\", "/")
		if sources[sourceFilename].Error != nil {
			e := fmt.Errorf("error reading source '%s': '%v'", sourceFilename, sources[sourceFilename].Error)
			return "", fmt.Errorf(utils.ErrMsg, result.ID, e)
		}
		if node.MethodLine < 1 || node.MethodLine > len(sources[sourceFilename].Source) {
			e := fmt.Errorf("method line number %d is out of range", node.MethodLine)
			return "", fmt.Errorf(utils.ErrMsg, result.ID, e)
		}
		if node.Line < 1 || node.Line > len(sources[sourceFilename].Source) {
			e := fmt.Errorf("node line number %d is out of range", node.Line)
			return "", fmt.Errorf(utils.ErrMsg, result.ID, e)
		}
		methodSpec := MethodSpec{Filename: sourceFilename, Name: node.Method, Line: node.MethodLine}
		if _, exists := nodesInMethods[methodSpec]; !exists {
			nodesInMethods[methodSpec] = []*NodeLine{}
			methods = append(methods, methodSpec)
		}
		nodesInMethods[methodSpec] = append(nodesInMethods[methodSpec], &NodeLine{Index: i, Line: node.Line})
	}
	for _, m := range methods {
		lineNumbers := nodesInMethods[m]
		sort.Slice(lineNumbers, func(i, j int) bool {
			return lineNumbers[i].Line < lineNumbers[j].Line
		})
		sourcePrompt = append(sourcePrompt, fmt.Sprintf("%s//FILE: %s:%d", sources[m.Filename].Source[m.Line-1], m.Filename, m.Line))
		for i := 0; i < len(lineNumbers); i++ {
			index := lineNumbers[i].Index
			line := lineNumbers[i].Line
			node := result.Data.Nodes[index]

			var edge string
			if index == 0 {
				edge = " (input)"
			} else if index == len(result.Data.Nodes)-1 {
				edge = " (output)"
			} else {
				edge = ""
			}

			// change UnknownReference to something more informational like VariableReference or TypeNameReference
			nodeType := node.DomType
			if node.DomType == "UnknownReference" {
				if node.TypeName == "" {
					nodeType = "VariableReference"
				} else {
					nodeType = node.TypeName + "Reference"
				}
			}

			if i == 0 {
				if line != m.Line {
					if line-m.Line > 1 {
						sourcePrompt = append(sourcePrompt, "// ...")
					}
					sourcePrompt = append(sourcePrompt, sources[m.Filename].Source[line-1]+
						fmt.Sprintf("//SAST Node #%d%s: %s (%s)", index, edge, node.Name, nodeType))
				} else {
					sourcePrompt[len(sourcePrompt)-1] += fmt.Sprintf("//SAST Node #%d%s: %s (%s)", index, edge, node.Name, nodeType)
				}
			} else {
				if line != lineNumbers[i-1].Line {
					if line-lineNumbers[i-1].Line > 1 {
						sourcePrompt = append(sourcePrompt, "// ...")
					}
					sourcePrompt = append(sourcePrompt, sources[m.Filename].Source[lineNumbers[i].Line-1]+
						fmt.Sprintf("//SAST Node #%d%s: %s (%s)", index, edge, node.Name, nodeType))
				} else {
					sourcePrompt[len(sourcePrompt)-1] += fmt.Sprintf("//SAST Node #%d%s: %s (%s)", index, edge, node.Name, nodeType)
				}
			}
		}
		sourcePrompt = append(sourcePrompt, "// ...")
	}
	return strings.Join(sourcePrompt, "\n"), nil
}

// findElement finds the first occurrence of the element in the text. It looks for several variations of the element:
// **X**, **X:**, **X, **x**, **x:**, **x
func findElement(text, element string) (string, int) {
	alternatives := []struct {
		prefix string
		body   string
		suffix string
	}{
		{utils.Bold, strings.ToLower(element), utils.Bold},
		{utils.Bold, strings.ToLower(element), utils.Bold2},
		{utils.Bold, strings.ToLower(element), ""},
		{"", strings.ToLower(element), ""},
	}

	lowerText := strings.ToLower(text)
	for _, alternative := range alternatives {
		needle := alternative.prefix + alternative.body + alternative.suffix
		if i := strings.Index(lowerText, needle); i >= 0 {
			return needle, i
		}
		trimmedNeedle := strings.ReplaceAll(needle, " ", "")
		if trimmedNeedle != needle {
			e, i := findWithExtraSpaces(lowerText, needle)
			if i != -1 {
				return e, i
			}
		}
	}
	return "", -1

}

func replaceIdentifierTitleIfNeeded(input, identifier, identifierDescription string) string {
	return strings.Replace(input, identifier, fmt.Sprintf(utils.IdentifierTitleFormat, identifier, identifierDescription), 1)
}

// findWithExtraSpaces finds the first occurrence of the needle in the text given that the needle has one internal space.
// It looks for the needle with multiple spaces between the words.
func findWithExtraSpaces(text string, needle string) (string, int) {
	// split the needle into words
	words := strings.Split(needle, " ")
	if len(words) != 2 {
		return "", -1
	}
	// find the first word
	i := strings.Index(text, words[0])
	if i == -1 {
		return "", -1
	}
	// find the second word
	j := strings.Index(text[i+len(words[0]):], words[1])
	if j == -1 {
		return "", -1
	}
	spaces := strings.Repeat(" ", j)
	needle = words[0] + spaces + words[1]
	return needle, i
}

func getDigits(text string) string {
	e, s := -1, -1
	for i, r := range text {
		if unicode.IsDigit(r) && s == -1 {
			s = i
		} else if !unicode.IsDigit(r) && s != -1 {
			e = i
			break
		}
	}
	if e == -1 {
		e = len(text)
	}
	if s > 0 && !unicode.IsSpace(rune(text[s-1])) ||
		e < len(text) && (!unicode.IsSpace(rune(text[e])) && text[e] != '*') ||
		s == -1 {
		return ""
	}
	return text[s:e]
}
