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
		wantErr    bool
	}{
		{"TestBuildPromptHappy", args{"testdata/cx_result.json", "13588507", "testdata/sources"}, systemPrompt, userPrompt("SQL_Injection", "Java", userPromptCode), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSystem, gotUser, err := BuildPrompt(tt.args.resultsFile, tt.args.resultId, tt.args.sourcePath)
			if (err != nil) != tt.wantErr {
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

func userPrompt(query, language, code string) string {
	return fmt.Sprintf(userPromptTemplate, query, language, code)
}
