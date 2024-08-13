package sast_result_remediation

import (
	"fmt"
	"testing"
)

const userPromptCode = `  public AttackResult completed(@RequestParam String query) {// SqlInjectionLesson3.java:53//SAST Node #0 (input): query (ParamDecl)
    return injectableQuery(query);//SAST Node #1: query (StringReference)
// method continues ...
  protected AttackResult injectableQuery(String query) {// SqlInjectionLesson3.java:57//SAST Node #2: query (ParamDecl)
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        Statement checkStatement =
            connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
        statement.executeUpdate(query);//SAST Node #3: query (StringReference)//SAST Node #4 (output): executeUpdate (MethodInvokeExpr)
// method continues ...`

const userPromptCode2 = `  public AttackResult completed(@RequestParam String query) {// SqlInjectionLesson2.java:58//SAST Node #0 (input): query (ParamDecl)
    return injectableQuery(query);//SAST Node #1: query (StringReference)
// method continues ...
  protected AttackResult injectableQuery(String query) {// SqlInjectionLesson2.java:62//SAST Node #2: query (ParamDecl)
    try (var connection = dataSource.getConnection()) {
      Statement statement = connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
      ResultSet results = statement.executeQuery(query);//SAST Node #3: query (StringReference)//SAST Node #4 (output): executeQuery (MethodInvokeExpr)
// method continues ...`

const userPromptCode3 = `    $.get("challenge/8/votes/", function (votes) {// /challenge8.js:7//SAST Node #0 (input): votes (ParamDecl)
            var totalVotes = 0;
            for (var i = 1; i <= 5; i++) {
                totalVotes = totalVotes + votes[i];
            }
            console.log(totalVotes);
            for (var i = 1; i <= 5; i++) {
                var percent = votes[i] * 100 / totalVotes;
                console.log(percent);
                var progressBar = $('#progressBar' + i);
                progressBar.width(Math.round(percent) * 2 + '%');
                $("#nrOfVotes" + i).html(votes[i]);//SAST Node #1: votes (objectReference)//SAST Node #2 (output): html (MethodInvokeExpr)
// method continues ...`

func TestBuildPrompt(t *testing.T) {
	type args struct {
		resultsFile string
		resultId    string
		sourcePath  string
	}
	tests := []struct {
		name       string
		args       args
		wantSystem string
		wantUser   string
		wantErr    error
	}{
		{"TestBuildPromptHappy", args{"testdata/cx_result.json", "13588507", "testdata/sources"},
			systemPrompt, userPrompt("SQL_Injection", "Java", userPromptCode), nil},
		{"TestBuildPromptFileNotFound", args{"invalidFile", "13588507", "testdata/sources"},
			"", "", fmt.Errorf("error reading and parsing SAST results file 'invalidFile': 'open invalidFile: no such file or directory'")},
		{"TestBuildPromptResultIdNotFound", args{"testdata/cx_result.json", "invalidResultId", "testdata/sources"},
			"", "", fmt.Errorf("error getting result for result ID 'invalidResultId': 'result ID invalidResultId not found'")},
		{"TestBuildPromptSourcesNotFound", args{"testdata/cx_result.json", "13588507", "invalidSources"},
			"", "", fmt.Errorf("error getting sources for result ID '13588507': 'open invalidSources/SqlInjectionLesson3.java: no such file or directory'")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSystem, gotUser, err := BuildPrompt(tt.args.resultsFile, tt.args.resultId, tt.args.sourcePath)
			if err != nil &&
				err.Error() != tt.wantErr.Error() {
				t.Errorf("BuildPrompt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSystem != tt.wantSystem {
				t.Errorf("BuildPrompt() gotSystem = %v, want %v", gotSystem, tt.wantSystem)
			}
			if gotUser != tt.wantUser {
				t.Errorf("BuildPrompt() gotUser = %v, want %v", gotUser, tt.wantUser)
			}
		})
	}
}

const (
	resultsFile = "testdata/cx_result.json"
	sourcePath  = "testdata/sources"
)

func TestBuildPromptsForLanguageAndQuery(t *testing.T) {
	type args struct {
		resultsFile string
		sourcePath  string
		language    string
		query       string
		resultId    string
	}
	tests := []struct {
		name string
		args args
		want []SastResultPrompt
	}{
		{"TestBuildPromptsForJavaSqlInjection",
			args{resultsFile: resultsFile, sourcePath: sourcePath, language: "Java", query: "SQL_Injection", resultId: ""},
			[]SastResultPrompt{
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "Java",
					Query:       "SQL_Injection",
					System:      systemPrompt,
					User:        userPrompt("SQL_Injection", "Java", userPromptCode),
					Error:       nil,
				},
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "Java",
					Query:       "SQL_Injection",
					System:      systemPrompt,
					User:        userPrompt("SQL_Injection", "Java", userPromptCode2),
					Error:       nil,
				},
			},
		},
		{"TestBuildPromptsForJavaScript",
			args{resultsFile: resultsFile, sourcePath: sourcePath, language: "JavaScript", query: "*", resultId: ""},
			[]SastResultPrompt{
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "JavaScript",
					Query:       "Client_DOM_Stored_XSS",
					System:      systemPrompt,
					User:        userPrompt("Client_DOM_Stored_XSS", "JavaScript", userPromptCode3),
					Error:       nil,
				},
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "JavaScript",
					Query:       "Client_DOM_Open_Redirect",
					System:      systemPrompt,
					User:        "",
					Error:       fmt.Errorf("error getting method Cxd39430bd: source '/backbone-min.js' is irrelevant for analysis"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildPromptsForLanguageAndQuery(tt.args.resultsFile, tt.args.language, tt.args.query, tt.args.sourcePath)
			if len(got) != len(tt.want) {
				t.Errorf("BuildPromptsForLanguageAndQuery() got = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if (got[i].Error != nil) &&
					got[i].Error.Error() != tt.want[i].Error.Error() {
					t.Errorf("BuildPromptsForLanguageAndQuery() gotErr = \n%v\nwantErr \n%v\n", got[i].Error, tt.want[i].Error)
					return
				}
				if got[i].System != tt.want[i].System {
					t.Errorf("BuildPromptsForLanguageAndQuery() gotSystem = \n%v\n, want \n%v\n", got[i].System, tt.want[i].System)
				}
				if got[i].User != tt.want[i].User {
					t.Errorf("BuildPromptsForLanguageAndQuery() gotUser = \n%v\n, want \n%v\n", got[i].User, tt.want[i].User)
				}
			}
		})
	}
}

func userPrompt(query, language, code string) string {
	return fmt.Sprintf(userPromptTemplate, query, language, code)
}
