package sast_result_remediation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const systemPrompt = `You are the Checkmarx AI Guided Remediation bot that answers technical questions related to the results of Checkmarx Static Application Security Testing (SAST). You analyze and understand both the technical aspects of the security results and common questions users may have about the results. You are capable of delivering clear, concise, and informative answers to help take appropriate action based on the findings. If a question asked is irrelevant to the mentioned source code or SAST result, answer 'I am the AI Guided Remediation assistant and can answer only on questions related to source code or SAST results or SAST Queries'.`

const (
	confidence      = "CONFIDENCE" // this is the expected confidence identifier
	explanation     = "EXPLANATION"
	fix             = "PROPOSED REMEDIATION"
	code            = "```"
	bold            = "**"
	bold2           = ":**"
	boldConfidence  = bold + confidence + bold
	boldExplanation = bold + explanation + bold
	boldFix         = bold + fix + bold
)

const (
	confidenceDescription  = " A score between 0 (low) and 100 (high) indicating the degree of confidence in the exploitability of this vulnerability in the context of your code. <br>"
	explanationDescription = " An OpenAI generated description of the vulnerability. <br>"
	fixDescription         = " A customized snippet, generated by OpenAI, that can be used to remediate the vulnerability in your code. <br>"
)

// This constant is used to format the identifiers (confidence, explanation, fix) and their descriptions with HTML tags
const identifierTitleFormat = "<span style=\"color: regular;\">%s</span><span style=\"color: grey; font-style: italic;\">%s</span>"

const userPromptTemplate = `Checkmarx Static Application Security Testing (SAST) detected the %s vulnerability (CWE-%d) within the provided %s code snippet. 
The attack vector is presented by a code snippet annotated by comments. There are two types of annotations:
1. Attack vector nodes: in the form ` + "`//SAST Node #X: element (element-type)`" + ` where X is the node index in the result, ` + "`element`" + ` is the name of the element through which the data flows, and the ` + "`element-type`" + ` is it's type. First and Last nodes are indicated by additional ` + "`(input)`" + ` and ` + "`(output)`" + ` respectively. 	
2. Method definitions: are annotated by a comment of the form ` + "`//FILE: /file-path/file-name:line`" + ` indicating its ` + "`file-path`" + `, ` + "`file-name`" + ` and ` + "`line`" + ` where the method begins.
An annotation comment can have multiple annotations. 
The code to review is at the end under the title **CODE TO REVIEW**.

Please review the code below and provide a confidence score ranging from 0 to 100.
A score of 0 means you believe the result is completely incorrect, unexploitable, and a false positive.
A score of 100 means you believe the result is completely correct, exploitable, and a true positive.

Instructions for confidence score computation:

1. The confidence score of a vulnerability which can be done from the Internet is much higher than from the local console.
2. The confidence score of a vulnerability which can be done by anonymous user is much higher than of an authenticated user.
3. The confidence score of a vulnerability with a vector starting with a stored input (like from files/db etc) cannot be more than 50.
This is also known as a second-order vulnerability
4. The confidence score of a vulnerability with a vector containing nodes in test code, cannot be more than 50 since it does not run in production. Test code is identified either by the file name containing the word 'test' or the file path containing the word 'test'. The same reasoning applies to file names or file paths containing the words 'demo', 'example', 'sample' or the like. These also do not run in production.
5. Pay special attention to the input and output nodes and see if they match the expected input and output for the vulnerability found. If the actual input or output does not match the expected, the confidence score cannot be no more than 50. For example, writing to a log as the output of a Reflected XSS should get a very low score.
6. If a node in the vulnerability vector is a sanitization node, the confidence score should be lower, even if the sanitization is not reliable.
7. If the vulnerability vector is hard to read or follow because it is long or complex, the confidence score should be lower.
8. If the vulnerability vector is hard reproduce is a test environment, the confidence score should be lower.
9. If you don't find enough evidence about a vulnerability, just lower the score.
10. If you are not sure, just lower the confidence - we don't want to have false positive results with a high confidence score.

Please provide a brief explanation for your confidence score, don't mention all the instruction above.

Next, please provide code that remediates the vulnerability so that a developer can copy paste instead of the snippet above.

Your analysis MUST be presented in the following format:
` + bold + confidence + bold +
	` number
` + "\n" + bold + explanation + bold +
	` short_text
` + "\n" + bold + fix + bold +
	` fixed_snippet

**CODE TO REVIEW**
IMPORTANT: pay special attention to the ANNOTATED LINES in the following code, they provide important details regarding the vulnerability and the relevance of code to production or other environments.
` + code + `
%s
` + code

type ParsedResponse struct {
	Confidence   int
	Explanation  string
	Fix          string
	Introduction string
}

func (pb *PromptBuilder) CreatePromptsForResults(results []*Result, cleanSources map[string][]string, promptTemplate *SastResultPrompt) []*SastResultPrompt {
	var prompts []*SastResultPrompt
	for _, result := range results {
		prompt := &SastResultPrompt{
			ResultsFile: promptTemplate.ResultsFile,
			SourcePath:  promptTemplate.SourcePath,
			Language:    result.Data.LanguageName,
			Query:       result.Data.QueryName,
			ResultId:    result.ID,
		}
		prompt.System = GetSystemPrompt()
		sources := copyCleanSources(cleanSources)
		prompt.User, prompt.Error = pb.CreateUserPrompt(result, sources)
		prompts = append(prompts, prompt)
	}
	return prompts
}

func copyCleanSources(sources map[string][]string) map[string][]string {
	cleanSources := make(map[string][]string)
	for k, v := range sources {
		cleanSources[k] = append([]string(nil), v...)
	}
	return cleanSources
}

func GetSystemPrompt() string {
	return systemPrompt
}

func (pb *PromptBuilder) CreateUserPrompt(result *Result, sources map[string][]string) (string, error) {
	var promptSource string
	var err error
	if pb.NodeLinesOnly {
		promptSource, err = createSourceForPromptWithNodeLinesOnly(result, sources)
		if err != nil {
			return "", err
		}
	} else {
		promptSource, err = createSourceForPrompt(result, sources)
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf(userPromptTemplate, result.Data.QueryName, result.VulnerabilityDetails.CweID, result.Data.LanguageName, promptSource), nil
}

// createSourceForPromptWithNodeLinesOnly creates the comment-annotated source snippet for the SAST prompt.
// It iterates over the nodes in the result and collects the source lines from the nodes and the method lines.
// It annotates the lines with the node information.
func createSourceForPromptWithNodeLinesOnly(result *Result, sources map[string][]string) (string, error) {
	return "", nil
}

// createSourceForPrompt creates the comment-annotated source snippet for the SAST prompt.
// It iterates over the nodes in the result, collects the source lines from the beginning of the method to the node line,
// and annotates the lines with the node information. Whenever a new method is encountered, it fetches the method lines.
func createSourceForPrompt(result *Result, sources map[string][]string) (string, error) {
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
			m, err := GetMethodByMethodLine(sourceFilename, sources[sourceFilename], node.MethodLine, node.Line, false)
			if err != nil {
				return "", fmt.Errorf("error getting method %s: %v", node.Method, err)
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
				m, err := GetMethodByMethodLine(sourceFilename, sources[sourceFilename], methodIndex.Line, node.Line, true)
				if err != nil {
					return "", fmt.Errorf("error getting method %s: %v", node.Method, err)
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

func GetMethodByMethodLine(filename string, lines []string, methodLineNumber, nodeLineNumber int, tagged bool) ([]string, error) {
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

func ParseResponse(response string) (*ParsedResponse, error) {
	parsedResponse := &ParsedResponse{}
	c, i := findElement(response, confidence)
	if i == -1 {
		return parsedResponse, fmt.Errorf("confidence not found in response")
	}
	parsedResponse.Introduction = response[:i]
	e, j := findElement(response, explanation)
	if j == -1 {
		return parsedResponse, fmt.Errorf("explanation not found in response")
	}
	confidenceText := response[i+len(c) : j]
	f, k := findElement(response, fix)
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

// findElement finds the first occurrence of the element in the text. It looks for several variations of the element:
// **X**, **X:**, **X, **x**, **x:**, **x
func findElement(text, element string) (string, int) {
	alternatives := []struct {
		prefix string
		body   string
		suffix string
	}{
		{bold, strings.ToLower(element), bold},
		{bold, strings.ToLower(element), bold2},
		{bold, strings.ToLower(element), ""},
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

func AddDescriptionForIdentifier(responseContent []string) []string {
	identifiersDescription := map[string]string{
		boldConfidence:  confidenceDescription,
		boldExplanation: explanationDescription,
		boldFix:         fixDescription,
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

func replaceIdentifierTitleIfNeeded(input, identifier, identifierDescription string) string {
	return strings.Replace(input, identifier, fmt.Sprintf(identifierTitleFormat, identifier, identifierDescription), 1)
}
