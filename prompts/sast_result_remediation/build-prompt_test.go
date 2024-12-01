package sast_result_remediation

import (
	"fmt"
	"testing"
)

const userPromptCode = `  public AttackResult completed(@RequestParam String query) {//FILE: SqlInjectionLesson3.java:53//SAST Node #0 (input): query (ParamDecl)
    return injectableQuery(query);//SAST Node #1: query (StringReference)
// method continues ...
  protected AttackResult injectableQuery(String query) {//FILE: SqlInjectionLesson3.java:57//SAST Node #2: query (ParamDecl)
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        Statement checkStatement =
            connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
        statement.executeUpdate(query);//SAST Node #3: query (StringReference)//SAST Node #4 (output): executeUpdate (MethodInvokeExpr)
// method continues ...`

const userPromptCode2 = `  public AttackResult completed(@RequestParam String query) {//FILE: SqlInjectionLesson2.java:58//SAST Node #0 (input): query (ParamDecl)
    return injectableQuery(query);//SAST Node #1: query (StringReference)
// method continues ...
  protected AttackResult injectableQuery(String query) {//FILE: SqlInjectionLesson2.java:62//SAST Node #2: query (ParamDecl)
    try (var connection = dataSource.getConnection()) {
      Statement statement = connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
      ResultSet results = statement.executeQuery(query);//SAST Node #3: query (StringReference)//SAST Node #4 (output): executeQuery (MethodInvokeExpr)
// method continues ...`

const userPromptCode3 = `    $.get("challenge/8/votes/", function (votes) {//FILE: /challenge8.js:7//SAST Node #0 (input): votes (ParamDecl)
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
			systemPrompt, userPrompt("SQL_Injection", 89, "Java", userPromptCode), nil},
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
	resultsFile     = "testdata/cx_result.json"
	sourcePath      = "testdata/sources"
	resultsListFile = "testdata/results_list.txt"
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
			args{resultsFile: resultsFile, sourcePath: sourcePath, language: "java", query: "sql_Injection", resultId: ""},
			[]SastResultPrompt{
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "Java",
					Query:       "SQL_Injection",
					System:      systemPrompt,
					User:        userPrompt("SQL_Injection", 89, "Java", userPromptCode),
					Error:       nil,
				},
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "Java",
					Query:       "SQL_Injection",
					System:      systemPrompt,
					User:        userPrompt("SQL_Injection", 89, "Java", userPromptCode2),
					Error:       nil,
				},
			},
		},
		{"TestBuildPromptsForJavaScript",
			args{resultsFile: resultsFile, sourcePath: sourcePath, language: "javascript", query: "*", resultId: ""},
			[]SastResultPrompt{
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "JavaScript",
					Query:       "Client_DOM_Stored_XSS",
					System:      systemPrompt,
					User:        userPrompt("Client_DOM_Stored_XSS", 79, "JavaScript", userPromptCode3),
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

func TestBuildPromptsForResultsList(t *testing.T) {
	type args struct {
		resultsFile     string
		sourcePath      string
		resultsListFile string
	}
	tests := []struct {
		name string
		args args
		want []SastResultPrompt
	}{
		{"TestBuildPromptsForResultsList",
			args{resultsFile: resultsFile, sourcePath: sourcePath, resultsListFile: resultsListFile},
			[]SastResultPrompt{
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "Java",
					Query:       "SQL_Injection",
					System:      systemPrompt,
					User:        userPrompt("SQL_Injection", 89, "Java", userPromptCode),
					Error:       nil,
				},
				{
					ResultsFile: resultsFile,
					SourcePath:  sourcePath,
					Language:    "Java",
					Query:       "SQL_Injection",
					System:      systemPrompt,
					User:        userPrompt("SQL_Injection", 89, "Java", userPromptCode2),
					Error:       nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildPromptsForResultsList(tt.args.resultsFile, tt.args.resultsListFile, tt.args.sourcePath)
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

func userPrompt(query string, cwe int, language string, code string) string {
	return fmt.Sprintf(userPromptTemplate, query, cwe, language, code)
}

const codeMissingNode = `    public String getRealPath(String path) {//FILE: JspCServletContext.java:296
        if (!myResourceBaseURL.getProtocol().equals("file")) {
            return null;
        }
        if (!path.startsWith("/")) {
            return null;
        }
        try {
            URL url = getResource(path);
            if (url == null) {
                return null;
            }
            File f = new File(url.toURI());
            return f.getAbsolutePath();//SAST Node #0 (input): getAbsolutePath (MethodInvokeExpr)
// method continues ...
    public String getPathTranslated() {//FILE: ApplicationHttpRequest.java:450
        if (getPathInfo() == null || getServletContext() == null) {
            return null;
        }

        return getServletContext().getRealPath(getPathInfo());//SAST Node #1: getRealPath (MethodInvokeExpr)
// method continues ...
        public void service(HttpServletRequest request,//FILE: TomcatBaseTest.java:450
                            HttpServletResponse response)
                throws ServletException, IOException {

            String name;
            StringBuilder value;
            Object attribute;

            response.setContentType("text/plain");
            response.setCharacterEncoding("UTF-8");

            ServletContext ctx = this.getServletContext();
            HttpSession session = request.getSession(false);
            PrintWriter out = response.getWriter();

            out.println("CONTEXT-NAME: " + ctx.getServletContextName());
            out.println("CONTEXT-PATH: " + ctx.getContextPath());
            out.println("CONTEXT-MAJOR-VERSION: " + ctx.getMajorVersion());
            out.println("CONTEXT-MINOR-VERSION: " + ctx.getMinorVersion());
            out.println("CONTEXT-SERVER-INFO: " + ctx.getServerInfo());
            for (Enumeration<String> e = ctx.getInitParameterNames();
                 e.hasMoreElements();) {
                name = e.nextElement();
                out.println("CONTEXT-INIT-PARAM:" + name + ": " +
                            ctx.getInitParameter(name));
            }
            for (Enumeration<String> e = ctx.getAttributeNames();
                 e.hasMoreElements();) {
                name = e.nextElement();
                out.println("CONTEXT-ATTRIBUTE:" + name + ": " +
                            ctx.getAttribute(name));
            }
            out.println("REQUEST-CONTEXT-PATH: " + request.getContextPath());
            out.println("REQUEST-SERVER-NAME: " + request.getServerName());
            out.println("REQUEST-SERVER-PORT: " + request.getServerPort());
            out.println("REQUEST-LOCAL-NAME: " + request.getLocalName());
            out.println("REQUEST-LOCAL-ADDR: " + request.getLocalAddr());
            out.println("REQUEST-LOCAL-PORT: " + request.getLocalPort());
            out.println("REQUEST-REMOTE-HOST: " + request.getRemoteHost());
            out.println("REQUEST-REMOTE-ADDR: " + request.getRemoteAddr());
            out.println("REQUEST-REMOTE-PORT: " + request.getRemotePort());
            out.println("REQUEST-PROTOCOL: " + request.getProtocol());
            out.println("REQUEST-SCHEME: " + request.getScheme());
            out.println("REQUEST-IS-SECURE: " + request.isSecure());
            out.println("REQUEST-URI: " + request.getRequestURI());
            out.println("REQUEST-URL: " + request.getRequestURL());
            out.println("REQUEST-SERVLET-PATH: " + request.getServletPath());
            out.println("REQUEST-METHOD: " + request.getMethod());
            out.println("REQUEST-PATH-INFO: " + request.getPathInfo());
            out.println("REQUEST-PATH-TRANSLATED: " +//SAST Node #3 (output): println (MethodInvokeExpr)
                        request.getPathTranslated());//SAST Node #2: getPathTranslated (MethodInvokeExpr)
// method continues ...`

const codeTwoSimilarResults1 = `  public String logRequest(//FILE: Ping.java:47
      @RequestHeader("User-Agent") String userAgent, @RequestParam(required = false) String text) {//SAST Node #0 (input): text (ParamDecl)
    String logLine = String.format("%s %s %s", "GET", userAgent, text);//SAST Node #1: text (StringReference)//SAST Node #2: format (MethodInvokeExpr)//SAST Node #3: logLine (Declarator)
    log.debug(logLine);//SAST Node #4: logLine (StringReference)//SAST Node #5 (output): debug (MethodInvokeExpr)
// method continues ...`

const codeTwoSimilarResults2 = `  public String logRequest(//FILE: Ping.java:47
      @RequestHeader("User-Agent") String userAgent, @RequestParam(required = false) String text) {//SAST Node #0 (input): userAgent (ParamDecl)
    String logLine = String.format("%s %s %s", "GET", userAgent, text);//SAST Node #1: userAgent (StringReference)//SAST Node #2: format (MethodInvokeExpr)//SAST Node #3: logLine (Declarator)
    log.debug(logLine);//SAST Node #4: logLine (StringReference)//SAST Node #5 (output): debug (MethodInvokeExpr)
// method continues ...`

const jspCode = `    String jndiName = request.getParameter("jndiName");//FILE: jndi.jsp:18//SAST Node #0 (input): &#34;&#34;jndiName&#34;&#34; (StringLiteral)//SAST Node #1: getParameter (MethodInvokeExpr)//SAST Node #2: jndiName (Declarator)
// method continues ...
        Object obj = envCtx.lookup(jndiName);//FILE: jndi.jsp:24//SAST Node #3: jndiName (StringReference)//SAST Node #4 (output): lookup (MethodInvokeExpr)
// method continues ...`

const jspAndJavaCode = `<jsp:setProperty name="numguess" property="*"/>//FILE: numguess.jsp:25//SAST Node #0 (input): getParameterMap (MethodInvokeExpr)//SAST Node #1: set (MethodInvokeExpr)//SAST Node #2: numguess (NumberGuessBeanReference)
// method continues ...
<% if (numguess.getSuccess()) { %>//FILE: numguess.jsp:32//SAST Node #3: numguess (NumberGuessBeanReference)
// method continues ...
<% } else if (numguess.getNumGuesses() == 0) { %>//FILE: numguess.jsp:41//SAST Node #4: numguess (NumberGuessBeanReference)
// method continues ...
  Good guess, but nope.  Try <b><%= numguess.getHint() %></b>.//FILE: numguess.jsp:54//SAST Node #5: numguess (NumberGuessBeanReference)//SAST Node #7 (output): getHint (MethodInvokeExpr)
// method continues ...
    public String getHint() {//FILE: NumberGuessBean.java:48
        return "" + hint;//SAST Node #6: hint (StringReference)
// method continues ...`

const codeTwoMethodsWithSameName = `    void parseParameters() {//FILE: ApplicationHttpRequest.java:710

        if (parsedParams) {
            return;
        }

        parameters = new ParameterMap<>(getRequest().getParameterMap());//SAST Node #0 (input): getParameterMap (MethodInvokeExpr)//SAST Node #1: ParameterMap (ObjectCreateExpr)//SAST Node #2: parameters (MapReference)
// method continues ...
    public String getParameter(String name) {//FILE: ApplicationHttpRequest.java:394
        parseParameters();//SAST Node #3: parseParameters (MethodInvokeExpr)

        String[] value = parameters.get(name);//SAST Node #4: parameters (MapReference)//SAST Node #5: get (MethodInvokeExpr)//SAST Node #6: value (Declarator)
        if (value == null) {
            return null;
        }
        return value[0];//SAST Node #7: value (StringReference)
// method continues ...
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {//FILE: HostManagerServlet.java:163

        StringManager smClient = StringManager.getManager(Constants.Package, request.getLocales());

        // Identify the request parameters that we need
        String command = request.getPathInfo();
        if (command == null) {
            command = request.getServletPath();
        }
        String name = request.getParameter("name");//SAST Node #8: getParameter (MethodInvokeExpr)//SAST Node #9: name (Declarator)

        // Prepare our output writer to generate the response message
        response.setContentType("text/plain; charset=" + Constants.CHARSET);
        // Stop older versions of IE thinking they know best. We set text/plain
        // in the line above for a reason. IE's behaviour is unwanted at best
        // and dangerous at worst.
        response.setHeader("X-Content-Type-Options", "nosniff");
        PrintWriter writer = response.getWriter();

        // Process the requested command
        if (command == null) {
            writer.println(smClient.getString("hostManagerServlet.noCommand"));
        } else if (command.equals("/add")) {
            add(request, writer, name, false, smClient);//SAST Node #10: name (StringReference)
// method continues ...
    protected void add(HttpServletRequest request, PrintWriter writer, String name, boolean htmlMode,//FILE: HostManagerServlet.java:216//SAST Node #11: name (ParamDecl)
            StringManager smClient) {
        String aliases = request.getParameter("aliases");
        String appBase = request.getParameter("appBase");
        boolean manager = booleanParameter(request, "manager", false, htmlMode);
        boolean autoDeploy = booleanParameter(request, "autoDeploy", true, htmlMode);
        boolean deployOnStartup = booleanParameter(request, "deployOnStartup", true, htmlMode);
        boolean deployXML = booleanParameter(request, "deployXML", true, htmlMode);
        boolean unpackWARs = booleanParameter(request, "unpackWARs", true, htmlMode);
        boolean copyXML = booleanParameter(request, "copyXML", false, htmlMode);
        add(writer, name, aliases, appBase, manager, autoDeploy, deployOnStartup, deployXML, unpackWARs, copyXML,//SAST Node #12: name (StringReference)
// method continues ...
    protected synchronized void add(PrintWriter writer, String name, String aliases, String appBase, boolean manager,//FILE: HostManagerServlet.java:302//SAST Node #13: name (ParamDecl)
            boolean autoDeploy, boolean deployOnStartup, boolean deployXML, boolean unpackWARs, boolean copyXML,
            StringManager smClient) {
        if (debug >= 1) {
            log(sm.getString("hostManagerServlet.add", name));
        }

        // Validate the requested host name
        if (name == null || name.length() == 0) {//SAST Node #14: name (StringReference)
            writer.println(smClient.getString("hostManagerServlet.invalidHostName", name));
            return;
        }

        // Check if host already exists
        if (engine.findChild(name) != null) {
            writer.println(smClient.getString("hostManagerServlet.alreadyHost", name));
            return;
        }

        // Validate and create appBase
        File appBaseFile = null;
        File file = null;
        String applicationBase = appBase;
        if (applicationBase == null || applicationBase.length() == 0) {
            applicationBase = name;
        }
        file = new File(applicationBase);
        if (!file.isAbsolute()) {
            file = new File(engine.getCatalinaBase(), file.getPath());
        }
        try {
            appBaseFile = file.getCanonicalFile();
        } catch (IOException e) {
            appBaseFile = file;
        }
        if (!appBaseFile.mkdirs() && !appBaseFile.isDirectory()) {
            writer.println(smClient.getString("hostManagerServlet.appBaseCreateFail", appBaseFile.toString(), name));
            return;
        }

        // Create base for config files
        File configBaseFile = getConfigBase(name);//SAST Node #15: name (StringReference)
// method continues ...
    protected File getConfigBase(String hostName) {//FILE: HostManagerServlet.java:622//SAST Node #16: hostName (ParamDecl)
        File configBase = new File(context.getCatalinaBase(), "conf");
        if (!configBase.exists()) {
            return null;
        }
        if (engine != null) {
            configBase = new File(configBase, engine.getName());
        }
        if (installedHost != null) {
            configBase = new File(configBase, hostName);//SAST Node #17: hostName (StringReference)//SAST Node #18 (output): File (ObjectCreateExpr)
// method continues ...`

func TestBuildPromptForResults(t *testing.T) {
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
		{"TestBuildPromptForResultMissingNode", args{"testdata/sast_result_missing-node.json", "c1CrCRw4/3/A6q+6zwIhShQIe1I=", "testdata/sources"},
			systemPrompt, userPrompt("Stored_XSS", 79, "Java", codeMissingNode), nil},
		{"TestBuildPromptTwoSimilarResults1", args{"testdata/two_similar_results.json", "13893625", "testdata/sources"},
			systemPrompt, userPrompt("Log_Forging", 117, "Java", codeTwoSimilarResults1), nil},
		{"TestBuildPromptTwoSimilarResults2", args{"testdata/two_similar_results.json", "13893626", "testdata/sources"},
			systemPrompt, userPrompt("Log_Forging", 117, "Java", codeTwoSimilarResults2), nil},
		{"TestBuildPromptJspResult", args{"testdata/jsp_result.json", "vuKUhCJ5drCeY6IDB//eBu8wvkk=", "testdata/sources"},
			systemPrompt, userPrompt("LDAP_Injection", 90, "Java", jspCode), nil},
		{"TestBuildPromptJspAndJavaResult", args{"testdata/jsp_and_java_result.json", "XrM9Lk/bjJHxLOcn4XETGHJ1ko0=", "testdata/sources"},
			systemPrompt, userPrompt("Reflected_XSS_All_Clients", 79, "Java", jspAndJavaCode), nil},
		{"TestBuildPromptTwoMethodsWithSameName", args{"testdata/two_methods_with_same_name.json", "5LcQqrUhDTZWEVCBWwMWGhSm+00=", "testdata/sources"},
			systemPrompt, userPrompt("Input_Path_Not_Canonicalized", 73, "Java", codeTwoMethodsWithSameName), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSystem, gotUser, err := BuildPrompt(tt.args.resultsFile, tt.args.resultId, tt.args.sourcePath)
			if err != nil &&
				err.Error() != tt.wantErr.Error() {
				t.Errorf("BuildPrompt() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}
			if gotSystem != tt.wantSystem {
				t.Errorf("BuildPrompt() gotSystem = '%v', want '%v'", gotSystem, tt.wantSystem)
			}
			if gotUser != tt.wantUser {
				t.Errorf("BuildPrompt() gotUser = '%v', want '%v'", gotUser, tt.wantUser)
			}
		})
	}
}
