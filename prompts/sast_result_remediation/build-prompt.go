package sast_result_remediation

import "fmt"

func BuildPrompt(resultsFile string, resultId string, sourcePath string) (system, user string, err error) {

	system = ""
	user = ""
	err = nil
	results, err := ReadResultsSAST(resultsFile)
	if err != nil {
		return system, user, fmt.Errorf("Error '%v' reading results file '%s': ", err, resultsFile)
	}
	result, err := GetResultByID(results, resultId)
	if err != nil {
		return system, user, fmt.Errorf("Error '%v' getting result by ID '%s': ", err, resultId)
	}
	sources, err := GetSourcesForResult(result, sourcePath)
	if err != nil {
		return system, user, fmt.Errorf("Error '%v' getting sources for result ID '%s': ", err, resultId)
	}

	system = GetSystemPrompt()
	user, err = CreateUserPrompt(result, sources)
	if err != nil {
		return "", user, fmt.Errorf("Error '%v' creating user prompt for result ID '%s': ", err, resultId)
	}

	return system, user, err
}
