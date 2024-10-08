package sast_result_remediation

import (
	"fmt"
	"reflect"
	"testing"
)

const expectedOutputFormat = "<span style=\"color: regular;\">**CONFIDENCE:**</span><span style=\"color: grey; font-style: italic;\"> " +
	"A score between 0 (low) and 100 (high) indicating the degree of confidence in the exploitability of this vulnerability in the context of your code. " +
	"<br></span>%s<span style=\"color: regular;\">**EXPLANATION:**</span><span style=\"color: grey; font-style: italic;\"> " +
	"An OpenAI generated description of the vulnerability. <br></span>%s<span style=\"color: " +
	"regular;\">**PROPOSED REMEDIATION:**</span><span style=\"color: grey; font-style: italic;\"> " +
	"A customized snippet, generated by OpenAI, that can be used to remediate the vulnerability in your code. <br></span>%s"

func getExpectedOutput(confidenceNumber, explanationText, fixText string) string {
	return fmt.Sprintf(expectedOutputFormat, confidenceNumber, explanationText, fixText)
}

func TestAddDescriptionForIdentifiers(t *testing.T) {
	input := confidence + " 35 " + explanation + " this is a short explanation." + fix + " a fixed snippet"
	expected := getExpectedOutput(" 35 ", " this is a short explanation.", " a fixed snippet")
	output := getActual(input, t)

	if output[len(output)-1] != expected {
		t.Errorf("Expected %q, but got %q", expected, output)
	}
}

func TestAddNewlinesIfNecessarySomeNewlines(t *testing.T) {
	input := confidence + " 35 " + explanation + " this is a short explanation.\n" + fix + " a fixed snippet"
	expected := getExpectedOutput(" 35 ", " this is a short explanation.\n", " a fixed snippet")

	output := getActual(input, t)

	if output[len(output)-1] != expected {
		t.Errorf("Expected %q, but got %q", expected, output)
	}
}

func TestAddNewlinesIfNecessaryAllNewlines(t *testing.T) {
	input := confidence + " 35\n " + explanation + " this is a short explanation.\n" + fix + " a fixed snippet"
	expected := getExpectedOutput(" 35\n ", " this is a short explanation.\n", " a fixed snippet")

	output := getActual(input, t)

	if output[len(output)-1] != expected {
		t.Errorf("Expected %q, but got %q", expected, output)
	}
}

func TestParseResponse(t *testing.T) {
	introText := "this is some introductory text"
	goodConfidenceText := " 35\n"
	goodConfidenceText3 := " 35**\n"
	badConfidenceText := "0\nfailed0"
	confidenceValue := 35
	explanationText := " this is a short explanation.\n"
	fixText := "this is a fixed snippet"

	tests := []struct {
		name     string
		input    string
		expected *ParsedResponse
		err      error
	}{
		{"TestParseResponseHappy", introText + confidence + goodConfidenceText + explanation + explanationText + fix + fixText,
			&ParsedResponse{Introduction: introText, Confidence: confidenceValue, Explanation: explanationText, Fix: fixText}, nil},
		{"TestParseResponseHappy2", introText + confidence2 + goodConfidenceText + explanation + explanationText + fix + fixText,
			&ParsedResponse{Introduction: introText, Confidence: confidenceValue, Explanation: explanationText, Fix: fixText}, nil},
		{"TestParseResponseHappy3", introText + confidence3 + goodConfidenceText3 + explanation + explanationText + fix + fixText,
			&ParsedResponse{Introduction: introText, Confidence: confidenceValue, Explanation: explanationText, Fix: fixText}, nil},
		{"TestParseResponseNoConfidence", introText + goodConfidenceText + explanation + explanationText + fix + fixText,
			&ParsedResponse{Introduction: "", Confidence: 0, Explanation: "", Fix: ""},
			fmt.Errorf("confidence not found in response")},
		{"TestParseResponseNoExplanation", introText + confidence + goodConfidenceText + explanationText + fix + fixText,
			&ParsedResponse{Introduction: introText, Confidence: 0, Explanation: "", Fix: ""},
			fmt.Errorf("explanation not found in response")},
		{"TestParseResponseNoFix", introText + confidence + goodConfidenceText + explanation + explanationText + fixText,
			&ParsedResponse{Introduction: introText, Confidence: 0, Explanation: "", Fix: ""},
			fmt.Errorf("fix not found in response")},
		{"TestParseResponseBadConfidenceValue", introText + confidence + badConfidenceText + explanation + explanationText + fix + fixText,
			&ParsedResponse{Introduction: introText, Confidence: 0, Explanation: explanationText, Fix: fixText},
			fmt.Errorf("error converting confidence text to integer value: EOF")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := ParseResponse(tt.input)
			if err != nil &&
				(err.Error() != tt.err.Error()) {
				t.Errorf("ParseResponse() gotErr = \n%v\nwantErr \n%v\n", err, tt.err)
			}

			if !reflect.DeepEqual(*actual, *tt.expected) {
				t.Errorf("Expected %q, but got %q", *tt.expected, *actual)
			}
		})
	}
}

func getActual(input string, t *testing.T) []string {
	someText := "some text"
	response := []string{someText, someText, input}
	output := AddDescriptionForIdentifier(response)
	for i := 0; i < len(output)-1; i++ {
		if output[i] != response[i] {
			t.Errorf("All strings except last expected to stay the same")
		}
	}
	return output
}
