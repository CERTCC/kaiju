
import java.beans.PropertyChangeEvent;
import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import com.google.common.base.Verify;
import com.google.common.base.VerifyException;
import org.apache.commons.lang3.time.DurationFormatUtils;
import generic.jar.ResourceFile;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.ValueConverter;
import kaiju.common.KaijuHeadlessTool;
import kaiju.tools.ghihorn.GhiHornifierBuilder;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettingBuilder;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.format.GhiHornOutputFormatter;
import kaiju.tools.ghihorn.api.ApiDatabase;
import kaiju.tools.ghihorn.api.GhiHornApiDatabase;
import kaiju.tools.ghihorn.cmd.GhiHornCommand;
import kaiju.tools.ghihorn.cmd.GhiHornCommandListener;
import kaiju.tools.ghihorn.decompiler.GhiHornSimpleDecompiler;
import kaiju.tools.ghihorn.hornifer.GhiHornCommandEvent;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerConfig;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerController;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiSignature;
import kaiju.tools.ghihorn.tools.apianalyzer.json.ApiSignatureJsonParser;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerConfig;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerController;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

public class GhiHornHeadlessTool extends HeadlessScript
        implements GhiHornCommandListener, KaijuHeadlessTool {
    private class AddressConverter implements ValueConverter<Address> {

        @Override
        public Address convert(String value) {
            try {

                return currentProgram.getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(value);

            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
            return Address.NO_ADDRESS;
        }

        @Override
        public String valuePattern() {
            return null;
        }

        @Override
        public Class<? extends Address> valueType() {
            return Address.class;
        }
    }

    class GhiHornConfig {

        private final static String TIMEOUT = "timeout";
        private final static String PATH_ANALYZER = "pathanalyzer";
        private final static String API_ANALYZER = "apianalyzer";
        private final static String ENTRY_OPT = "entry";
        private final static String START_OPT = "start";
        private final static String GOAL_OPT = "goal";
        private final static String SIG_FILE_OPT = "sig_file";
        private final static String SIG_OPT = "sig";
        private final static String OUTPUT_FORMAT_OPT = "output_format";
        private final static String VARIABLE_OPT = "variables";
        private final static String SHOW_EXTERNAL_OPT = "show_external_funcs";
        private final static String SHOW_TEMP_VAR_OPT = "show_temp_vars";
        private final static String SHOW_STATE_OPT = "show_state";
        private final static String SHOW_UNSAT_OPT = "show_unsat";

        private OptionSpec<Void> helpOpt;
        private OptionSpec<Address> entrytOpt;
        private OptionSpec<Void> showUnsatOpt;
        private OptionSpec<Void> pathAnalyzerOpt;
        private OptionSpec<Void> apiAnalyzerOpt;
        private OptionSpec<Integer> timeoutOpt;
        private OptionSpec<Address> pathAnalyzerStartOpt;
        private OptionSpec<Address> pathAnalyzerGoalOpt;
        private OptionSpec<File> apiAnalyzerSigFileOpt;
        private OptionSpec<String> apiAnalyzerSigOpt;
        private OptionSpec<String> outputFormatOpt;
        private OptionSpec<String> variableOptionsOpt;
        private OptionSpec<Void> showAllStateOpt;
        private OptionSpec<Void> showExternalFuncsOpt;
        private OptionSpec<Void> showTempVariablesOpt;

        public String selectedTool = "";
        public int timeout = -1;
        public Address entryAddress = Address.NO_ADDRESS;
        public Address paStartAddress = Address.NO_ADDRESS;
        public Address paGoalAddress = Address.NO_ADDRESS;
        public ResourceFile sigFile = null;
        public String signature = "";
        public String outputFormat = "text";
        public boolean showGlobalVariables = true;
        public boolean showLocalVariables = true;
        public boolean showAllState = false;
        public boolean showTempVariables = false;
        public boolean showExternalFuncs = false;
        public boolean showUnsatAnswer = false;

        public String usage() {
            return new StringBuilder("GhiHorn configuration:\n")
                    .append(" * entry: entry address (omit to use Ghidra-defined entry point)\n")
                    .append("----\n")
                    .append("PathAnalyzer options\n")
                    .append(" * start: start address (omit to use Ghidra-defined entry point)\n")
                    .append(" * goal: goal address\n")
                    .append("----\n")
                    .append("ApiAnalyzer options\n")
                    .append(" * sig_file: Signature file (omit use use default)\n")
                    .append(" * sig: Signature to search for (omit to search for all)\n")
                    .append("----\n")
                    .append("Display options:\n")
                    .append(" * show_external_funcs: Show external functions in results. Defaults to hide\n")
                    .append(" * variables: show variables in results (all, none, global, local). Defaults to all\n")
                    .append(" * show_state: show complete state in results. Defaults to hide\n")
                    .append(" * show_temp_vars: show temporary variables in results. Defaults to hide\n")
                    .append("----\n")
                    .append("Output options\n")
                    .append(" * output_format: control output format (text or json). Defaults to text\n")
                    .append(" * timeout: time limit for analysis in seconds. Defaults to no timeout\n")
                    .append(" * show_unsat: show unsatisfiable results. Defaults to hide unsatisfiable\n")
                    .toString();
        }

        public String config() {
            StringBuilder out = new StringBuilder("GhiHorn configuration:\n");

            out.append("Using entry address: ").append(entryAddress).append("\n");

            if (config.selectedTool.equals(PathAnalyzerController.NAME)) {
                out.append("PathAnalyzer configuration\n")
                        .append(" * Start: ").append(paStartAddress)
                        .append("\n")
                        .append(" * Goal: ").append(paGoalAddress)
                        .append("\n");

            } else if (config.selectedTool.equals(ApiAnalyzerController.NAME)) {
                out.append("ApiAnalyzer configuration\n")
                        .append(" * Signature file used: ").append(sigFile.getName()).append("\n");
                if (signature.isBlank()) {
                    out.append(" * Searching for all signatures\n");
                } else {
                    out.append(" * Searching for ").append(signature).append("\n");
                }
            }
            out.append("Display options:\n");

            out.append(" * ").append((showExternalFuncs) ? "Showing external functions\n"
                    : "Hiding external functions\n");
            out.append(" * ").append((showGlobalVariables) ? "Showing global variables\n"
                    : "Hiding global variables\n");
            out.append(" * ").append((showLocalVariables) ? "Showing local variables\n"
                    : "Hiding local variables\n");
            out.append(" * ").append((showAllState) ? "Showing extended state information\n"
                    : "Hiding extended state information\n");
            out.append(" * ").append((!showTempVariables) ? "Hiding temporary variables\n"
                    : "Showing temporary variables\n");
            out.append(" * ").append((showUnsatAnswer) ? "Showing unsatisfiable resu;ts\n"
                    : "Hiding unsatisfiable\n");

            out.append("Output format: ").append(outputFormatOpt).append("\n");

            out.append("Timeout: ").append((timeout != -1) ? timeout : "None").append("\n");

            return out.toString();
        }


        /**
         * 
         * @return
         */
        public OptionParser parseOptions() {

            final OptionParser parser = new OptionParser();

            config.helpOpt = parser.accepts("help", "Prints help information").forHelp();

            Address entry = currentProgram.getSymbolTable()
                    .getExternalEntryPointIterator()
                    .next();

            config.entrytOpt =
                    parser.accepts(GhiHornConfig.ENTRY_OPT, "Entry address")
                            .withRequiredArg()
                            .withValuesConvertedBy(new AddressConverter())
                            .defaultsTo(entry);

            config.pathAnalyzerOpt =
                    parser.accepts(GhiHornConfig.PATH_ANALYZER, "Run PathAnalyzer");

            config.pathAnalyzerStartOpt =
                    parser.accepts(GhiHornConfig.START_OPT, "PathAnalyzer start address")
                            .withOptionalArg()
                            .withValuesConvertedBy(new AddressConverter());

            config.pathAnalyzerGoalOpt =
                    parser.accepts(GhiHornConfig.GOAL_OPT, "PathAnalyzer goal address")
                            .requiredIf(GhiHornConfig.PATH_ANALYZER)
                            .withRequiredArg()
                            .withValuesConvertedBy(new AddressConverter());

            // API
            config.apiAnalyzerOpt = parser.accepts(GhiHornConfig.API_ANALYZER, "Run ApiAnalyzer");

            config.apiAnalyzerSigFileOpt =
                    parser.accepts(GhiHornConfig.SIG_FILE_OPT,
                            "ApiAnalyzer signature file (omit to use default file")
                            .withOptionalArg()
                            .ofType(File.class);

            config.apiAnalyzerSigOpt =
                    parser.accepts(GhiHornConfig.SIG_OPT,
                            "ApiAnalyzer signature to search for (omit to search for all signatures)")
                            .withOptionalArg();

            // All
            config.timeoutOpt =
                    parser.accepts(GhiHornConfig.TIMEOUT, "Timout for analysis in seconds")
                            .withOptionalArg()
                            .ofType(Integer.class);

            config.outputFormatOpt =
                    parser.accepts(GhiHornConfig.OUTPUT_FORMAT_OPT, "Output format: text or json")
                            .withRequiredArg()
                            .defaultsTo("text");

            config.variableOptionsOpt =
                    parser.accepts(GhiHornConfig.VARIABLE_OPT,
                            "Types of variables to show. Acceptable options are none, all, global, local")
                            .withOptionalArg()
                            .defaultsTo("all");

            config.showExternalFuncsOpt =
                    parser.accepts(GhiHornConfig.SHOW_EXTERNAL_OPT,
                            "Show external function bodies in results");

            config.showAllStateOpt =
                    parser.accepts(GhiHornConfig.SHOW_STATE_OPT, "Show complete state in results");

            config.showUnsatOpt =
                    parser.accepts(GhiHornConfig.SHOW_UNSAT_OPT, "Show unsatifiable results");

            config.showAllStateOpt =
                    parser.accepts(GhiHornConfig.SHOW_TEMP_VAR_OPT,
                            "Show temporary variables in results");

            return parser;
        }

        /**
         * Generate the configuration
         * 
         * @param options
         * @throws VerifyException
         * @throws CancelledException
         */
        public void generate(OptionSet options) throws VerifyException, CancelledException {

            if (options.has(helpOpt)) {
                print(usage());
                throw new CancelledException();
            }

            Verify.verify(options.has(pathAnalyzerOpt) || options.has(apiAnalyzerOpt),
                    "Must specify a tool to run");

            if (options.hasArgument(timeoutOpt)) {
                timeout = (Integer) options.valueOf(timeoutOpt);
            }

            entryAddress = options.valueOf(entrytOpt);

            if (options.hasArgument(variableOptionsOpt)) {
                String varOpt = options.valueOf(variableOptionsOpt);
                if (varOpt.equalsIgnoreCase("all")) {
                    showGlobalVariables = true;
                    showLocalVariables = true;
                } else if (varOpt.equalsIgnoreCase("none")) {
                    showGlobalVariables = false;
                    showLocalVariables = false;
                } else if (varOpt.equalsIgnoreCase("global")) {
                    showGlobalVariables = true;
                    showLocalVariables = false;
                } else if (varOpt.equalsIgnoreCase("local")) {
                    showGlobalVariables = false;
                    showLocalVariables = true;
                }
            }

            if (options.hasArgument(outputFormatOpt)) {
                outputFormat = options.valueOf(outputFormatOpt);

                Verify.verify(
                        outputFormat.equals("text") || outputFormat.equals("json"),
                        "Invalid output format specified. Acceptable values are 'text' or 'json'");
            }

            showAllState = options.has(showAllStateOpt);
            showExternalFuncs = options.has(showExternalFuncsOpt);
            showTempVariables = options.has(showTempVariablesOpt);
            showUnsatAnswer = options.has(showUnsatOpt);

            if (options.has(pathAnalyzerOpt)) {
                selectedTool = PathAnalyzerController.NAME;

                if (options.hasArgument(pathAnalyzerStartOpt)) {
                    paStartAddress = options.valueOf(pathAnalyzerStartOpt);
                } else {
                    // Use the entry address
                    Iterable<Address> iterable =
                            () -> currentProgram.getSymbolTable().getExternalEntryPointIterator();
                    Stream<Address> epStream = StreamSupport.stream(iterable.spliterator(), false);
                    paStartAddress = epStream.findFirst().orElse(Address.NO_ADDRESS);
                }
                paGoalAddress = options.valueOf(pathAnalyzerGoalOpt);

                Verify.verify(
                        !paGoalAddress.equals(Address.NO_ADDRESS),
                        "Invalid goal address specified");
                Verify.verify(

                        !paStartAddress.equals(Address.NO_ADDRESS),
                        "Invalid start address specified");

            } else if (options.has(apiAnalyzerOpt)) {
                selectedTool = ApiAnalyzerController.NAME;
                if (!options.hasArgument(apiAnalyzerSigFileOpt)) {
                    sigFile = Application
                            .findDataFileInAnyModule(
                                    ApiAnalyzerController.DEFAULT_SIG_FILENAME);
                } else {
                    sigFile = new ResourceFile(options.valueOf(apiAnalyzerSigFileOpt));
                }
                if (options.hasArgument(apiAnalyzerSigOpt)) {
                    signature = options.valueOf(config.apiAnalyzerSigOpt);
                }
            } else {
                throw new VerifyException("Must specify a tool to run");
            }
            println("\n" + config());
        }
    }

    private GhiHornConfig config = new GhiHornConfig();
    private HashSet<GhiHornAnswer> results = new HashSet<>();
    private Map<GhiHornCommandEvent, String> eventConfig = new HashMap<>();
    private Instant startInstant;

    @Override
    public OptionParser getOptionParser() {
        return config.parseOptions();
    }

    @Override
    protected void run() {

        if (!isRunningHeadless()) {
            print("This script is meant to run GhiHorn in Headless mode");
            return;
        }

        // A program must be open in order to run the plugin
        if (currentProgram == null) {
            printerr("This script requires an open program");
            return;
        }

        try {
            OptionSet os = this.parse(getScriptArgs());
            config.generate(os);

        } catch (VerifyException vx) {
            printerr(vx.getMessage());
            return;

        } catch (CancelledException cx) {
            printerr("GhiHornHeadless terminated");
            return;
        } catch (Exception e) {
            e.printStackTrace();
            printerr(e.getMessage());
            return;
        }

        println("\n\n" + config.toString() + "\n\n");

        this.startInstant = Instant.now();

        try {

            ApiDatabase apiDb = new GhiHornApiDatabase(new GhiHornSimpleDecompiler());
            final ExecutorService executor = Executors.newFixedThreadPool(10);

            final List<Map<String, Object>> cmdList = configureCommands();

            for (Map<String, Object> params : cmdList) {

                executor.execute(new Runnable() {

                    @Override
                    public void run() {

                        GhiHornifierBuilder hornBuilder =
                                new GhiHornifierBuilder(config.selectedTool)
                                        .withDecompiler(new GhiHornSimpleDecompiler())
                                        .withApiDatabase(apiDb)
                                        .withEntryPoint(config.entryAddress)
                                        .withParameters(params);

                        GhiHornifier hornifier = hornBuilder.build();

                        GhiHornCommand cmd = new GhiHornCommand("cmd", hornifier);
                        cmd.addCommandListener(GhiHornHeadlessTool.this);
                        runCommand(cmd);
                    }
                });
            }

            println("GhiHorn running " + cmdList.size() + " commands");

            executor.shutdown();
            if (config.timeout != -1) {
                executor.awaitTermination(config.timeout, TimeUnit.SECONDS);
            } else {
                // Effectively wait indefinitely
                executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
            }

            displayResults();

        } catch (VerifyException ve) {
            // Some aspect of configuration failed
            printerr("\n" + ve.getMessage() + "\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 
     */
    private void displayResults() {

        GhiHornDisplaySettingBuilder dsBuilder = new GhiHornDisplaySettingBuilder();

        dsBuilder.showGlobalVariables(config.showGlobalVariables)
                .showLocalVariables(config.showLocalVariables)
                .showAllState(config.showAllState)
                .hideTempVariables(!config.showTempVariables)
                .hideExternalFuncs(!config.showExternalFuncs);

        if (config.outputFormat.equalsIgnoreCase("text")) {
            dsBuilder.generateText();
        } else {
            dsBuilder.generateJson();
        }

        GhiHornDisplaySettings displaySettings = dsBuilder.build();
        GhiHornOutputFormatter fmt = GhiHornOutputFormatter.create(displaySettings);
        long duration = Duration.between(startInstant, Instant.now()).toMillis();

        if (this.results.isEmpty()) {
            println("No results");
        } else {
            List<String> answers = new ArrayList<>();
            for (GhiHornAnswer result : this.results) {
                if (config.showUnsatAnswer) {
                    answers.add(fmt.format(result) + "\n---");
                } else if (result.status == GhiHornFixedpointStatus.Satisfiable) {
                    answers.add(fmt.format(result) + "\n---");
                }
            }

            StringBuilder out = new StringBuilder("\n\n\nAnalysis completed in ")
                    .append(DurationFormatUtils.formatDuration(duration,
                            "HH'hrs' mm'mins' ss'sec' "))
                    .append("\n")
                    .append(config.selectedTool)
                    .append(" found ")
                    .append(answers.size())
                    .append(" feasible paths");

            if (!answers.isEmpty()) {
                out.append("\nResults:\n\n");
                answers.forEach(a -> out.append(a).append("\n"));
            }
            out.append("\n\nFIN.");
            print(out.toString());
        }
    }


    /**
     * 
     * @return
     */
    private List<Map<String, Object>> configureCommands() throws VerifyException {

        final List<Map<String, Object>> settings = new ArrayList<>();

        if (config.selectedTool.equals("PathAnalyzer")) {

            PathAnalyzerConfig paConfig =
                    PathAnalyzerController.class.getAnnotation(PathAnalyzerConfig.class);

            registerCommandEvent(paConfig.events().statusUpdate(),
                    GhiHornCommandEvent.StatusMessage);
            registerCommandEvent(paConfig.events().resultUpdate(),
                    GhiHornCommandEvent.ResultReady);
            registerCommandEvent(paConfig.events().completeUpdate(),
                    GhiHornCommandEvent.Completed);
            registerCommandEvent(paConfig.events().cancelUpdate(),
                    GhiHornCommandEvent.Cancelled);


            final Map<String, Object> paArgs = new HashMap<>();
            paArgs.put(paConfig.startAddress(), config.paStartAddress);
            paArgs.put(paConfig.endAddress(), config.paGoalAddress);

            println("Running PathAnalyzer with start: " + config.paStartAddress + ", goal: "
                    + config.paGoalAddress);

            settings.add(paArgs);

        } else if (config.selectedTool.equals("ApiAnalyzer")) {

            ApiAnalyzerConfig apiConfig =
                    ApiAnalyzerController.class.getAnnotation(ApiAnalyzerConfig.class);

            Verify.verify(config.sigFile.exists(), "Cannot find signature file!");

            registerCommandEvent(apiConfig.events().statusUpdate(),
                    GhiHornCommandEvent.StatusMessage);
            registerCommandEvent(apiConfig.events().resultUpdate(),
                    GhiHornCommandEvent.ResultReady);
            registerCommandEvent(apiConfig.events().completeUpdate(),
                    GhiHornCommandEvent.Completed);
            registerCommandEvent(apiConfig.events().cancelUpdate(),
                    GhiHornCommandEvent.Cancelled);

            List<ApiSignature> signatures =
                    (new ApiSignatureJsonParser(config.sigFile.getFile(false))).parse();

            Verify.verify(signatures.size() > 0, "No valid signatures found");

            StringBuilder sb =
                    new StringBuilder("Running ApiAnalyzer\n");
            try {
                sb.append(" * signature file: " + config.sigFile.getCanonicalPath());
            } catch (IOException e) {
            }
            sb.append(" * signatures:\n");

            if (!config.signature.isBlank()) {
                signatures.removeIf(s -> !s.getName().equalsIgnoreCase(config.signature));
            }

            // Each signature will get a command
            for (ApiSignature sig : signatures) {

                sb.append("  - ").append(sig).append("\n");
                settings.add(new HashMap<>() {
                    {
                        put(apiConfig.signatures(), sig);
                    }
                });
            }
        }

        return settings;

    }

    /**
     * Receive events from the ApiAnalyzer command, either log or output
     */
    @Override
    public void propertyChange(PropertyChangeEvent evt) {

        final String propName = evt.getPropertyName();

        if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.StatusMessage))) {
            String status = (String) evt.getNewValue();
            println(status);

        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.Completed))) {
            println("\n\nCompleted");


        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.Cancelled))) {
            println("\n\nCanceled");

        } else if (propName
                .equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.ResultReady))) {
            GhiHornAnswer ans = (GhiHornAnswer) evt.getNewValue();
            results.add(ans);


        } else {
            Msg.info(this, "Unknown event received: " + propName);
        }
    }


    @Override
    public Map<GhiHornCommandEvent, String> getCommandEvents() {

        return this.eventConfig;
    }


    @Override
    public void registerCommandEvent(String id, GhiHornCommandEvent evt) {
        this.eventConfig.put(evt, id);

    }
}
