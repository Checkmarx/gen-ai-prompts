package sast_result_remediation

import "fmt"

func BuildPrompt(resultsFile string, resultId string, sourcePath string) (system, user string, err error) {

	system = ""
	user = ""
	err = nil
	results, err := ReadResultsSAST(resultsFile)
	if err != nil {
		return system, user, fmt.Errorf("Error reading and parsing SAST results file '%s': '%v'", resultsFile, err)
	}
	result, err := GetResultByID(results, resultId)
	if err != nil {
		return system, user, fmt.Errorf("Error getting result for result ID '%s': '%v'", resultId, err)
	}
	sources, err := GetSourcesForResult(result, sourcePath)
	if err != nil {
		return system, user, fmt.Errorf("Error getting sources for result ID '%s': '%v'", resultId, err)
	}

	system = GetSystemPrompt()
	user, err = CreateUserPrompt(result, sources)
	if err != nil {
		return "", user, fmt.Errorf("Error creating prompt for result ID '%s': '%v'", resultId, err)
	}

	return system, user, err
}
