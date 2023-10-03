package kaiju.ghihorn;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import com.google.gson.Gson;
import generic.stl.Pair;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.base.project.GhidraProject;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.GhiHornifierBuilder;
import kaiju.tools.ghihorn.api.ApiDatabase;
import kaiju.tools.ghihorn.decompiler.GhiHornSimpleDecompiler;
import kaiju.tools.ghihorn.hornifer.GhiHornCommandEvent;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerConfig;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerController;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiFunction;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiSignature;
import kaiju.tools.ghihorn.tools.apianalyzer.json.SignatureEntry;
import kaiju.tools.ghihorn.tools.apianalyzer.json.SignaturesType;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerConfig;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerController;

public class GhiHornTestEnv {

    public static final String GHIHORN_TEST_DIR = "GHIHORN_TEST_DIR";

    private GhidraProject project;
    private TestEnv env;
    private Map<String, Program> loadedTestPrograms;
    private Map<String, List<HighFunction>> loadedDecompiledPrograms;
    private Path ghihornTestDirectory;

    public GhiHornTestEnv(final TestEnv e) throws IOException {
        this.env = e;
        this.loadedTestPrograms = new HashMap<>();
        this.loadedDecompiledPrograms = new HashMap<>();
    }

    public void configure() throws Exception {
    
        // get the directory from the environment variable KAIJU_AUTOCATS_DIR
        // at this point, gradle should have checked that this is a real path, so just use it
        // TODO: is there a better way to confirm this is an AUTOCATS path first?
        String autocatsDirString = System.getenv("KAIJU_AUTOCATS_DIR");
        Path autocatsTopDirectory = Path.of(autocatsDirString);
        
        // get dir for the ghihorn-specific test files
        ghihornTestDirectory = autocatsTopDirectory.resolve("exe/ghihorn");

        this.project =
                GhidraProject.createProject(ghihornTestDirectory.toString(), "GhiHornTest", true);

    }

    public void dispose() {
        this.project.close();
    }

    /**
     * @return the env
     */
    public TestEnv getEnv() {
        return env;
    }

    /**
     * 
     * @param bytesString
     * @param lang
     * @return
     * @throws Exception
     */
    public Program makeTestProgram(String programName, String byteString,
            List<String> functionStarts, String lang) {

        try {
            final ProgramBuilder builder = new ProgramBuilder(programName, lang);
            Program program = builder.getProgram();

            builder.createMemory(programName, "0x1000", 4096);
            builder.setBytes("0x1000", byteString);

            // create at least one function ... this seems to effect the accuracy of
            // function, in particular decompilation
            if (functionStarts != null) {
                functionStarts.forEach(builder::createFunction);
            } else {
                builder.createFunction("0x1000");
            }

            builder.disassemble("0x1000", byteString.length());

            builder.analyze();

            return program;
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return null;
    }


    /**
     * Decompile helper
     * 
     * @param program
     * @return
     */
    public List<HighFunction> decompile(Program program) {
        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);
            List<HighFunction> funcList = new ArrayList<>();
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                DecompileResults decompResults = decompiler.decompileFunction(f,
                        DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
                funcList.add(decompResults.getHighFunction());
            }

            return funcList;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Build a test program with many functions
     * 
     * @param programByteString
     * @param language
     * @return
     */
    public List<HighFunction> decompileTestProgram(String programName, String programByteString,
            List<String> functions,
            String language) {

        // Cache the decompiled programs

        if (loadedDecompiledPrograms.containsKey(programByteString)) {
            return loadedDecompiledPrograms.get(programByteString);
        }
        try {

            List<HighFunction> decompiledProgram =
                    decompile(makeTestProgram(programName, programByteString, functions, language));
            this.loadedDecompiledPrograms.put(programByteString, decompiledProgram);

            return decompiledProgram;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Build a test program with many functions
     * 
     * @param programByteString
     * @param language
     * @return
     */
    public Program buildTestProgram(String programName, String programByteString,
            List<String> functions,
            String language) {

        // Cache the decompiled programs

        if (loadedTestPrograms.containsKey(programByteString)) {
            return loadedTestPrograms.get(programByteString);
        }
        try {

            Program p = makeTestProgram(programName, programByteString, functions, language);
            this.loadedTestPrograms.put(programByteString, p);

            return p;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }



    /**
     * Build a test function
     * 
     * @param bytesString
     * @param lang
     * @return
     */
    public HighFunction buildTestFunction(String programName, String bytesString, String lang) {
        try {
            return decompile(makeTestProgram(programName, bytesString, null, lang)).get(0);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<HighFunction> importAndDecompileProgram(final String programName, String string,
            List<String> list, String x86) {
        if (this.loadedDecompiledPrograms.containsKey(programName)) {
            return this.loadedDecompiledPrograms.get(programName);
        }
        try {
            Program p = importTestProgram(programName);
            List<HighFunction> hfList = decompile(p);
            this.loadedDecompiledPrograms.put(programName, hfList);

            return hfList;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    public List<HighFunction> importAndDecompileProgram(final String programName) {
        if (this.loadedDecompiledPrograms.containsKey(programName)) {
            return this.loadedDecompiledPrograms.get(programName);
        }
        try {
            Program p = importTestProgram(programName);
            List<HighFunction> hfList = decompile(p);
            this.loadedDecompiledPrograms.put(programName, hfList);

            return hfList;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    public static byte[] asByteArray(String hex) {
        hex = hex.replace(" ", "");
        byte[] bts = new byte[hex.length() / 2];
        for (int i = 0; i < bts.length; i++) {
            bts[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2),
                    16);
        }

        return bts;
    }

    public static File asFile(String hex) {
        try {
            File outputFile = File.createTempFile("tmp", null);

            try (FileOutputStream outputStream =
                    new FileOutputStream(outputFile)) {

                outputStream.write(asByteArray(hex));

                return outputFile;
            }

        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
        return null;

    }

    public Program importTestProgram(File exe) throws CancelledException, DuplicateNameException, InvalidNameException, VersionException, IOException {

        // Import the program
        Program p = env.getGhidraProject().importProgram(exe);
        env.open(p);

        env.getGhidraProject().analyze(p, true);

        // And mark it as analyzed? Ok ghidra whatever.
        GhidraProgramUtilities.markProgramAnalyzed(p);

        return p;
    }

    /**
     * 
     * @param programName
     * @return
     */
    public Program importTestProgram(String programName) throws FileNotFoundException {
        if (this.loadedTestPrograms.containsKey(programName)) {
            return this.loadedTestPrograms.get(programName);
        }
        try (Stream<Path> walk = Files.walk(Paths.get(ghihornTestDirectory.resolve("").toString()))) {

            Set<File> result = walk.filter(Files::isRegularFile)
                    .filter(f -> f.getFileName().toFile().getName().equals(programName))
                    .map(x -> x.toFile())
                    .collect(Collectors.toSet());

            if (!result.isEmpty()) {

                final File exe = result.iterator().next();

                return importTestProgram(exe);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        throw new FileNotFoundException("Cannot load " + programName);
    }

    public Pair<GhiHornEventListener, GhiHornifier> setUpPathAnalyzer(Address entry, Address start, Address end,
            ApiDatabase apiDb) throws Exception {

        GhiHornEventListener listener = new GhiHornEventListener();
        PathAnalyzerConfig configuration =
                PathAnalyzerController.class.getAnnotation(PathAnalyzerConfig.class);
        listener.registerCommandEvent(configuration.events().resultUpdate(),
                GhiHornCommandEvent.ResultReady);
        listener.registerCommandEvent(configuration.events().statusUpdate(),
                GhiHornCommandEvent.StatusMessage);
        listener.registerCommandEvent(configuration.events().completeUpdate(),
                GhiHornCommandEvent.Completed);
        listener.registerCommandEvent(configuration.events().cancelUpdate(),
                GhiHornCommandEvent.Cancelled);

        Map<String, Object> parameters = new HashMap<>() {
            {
                put(configuration.startAddress(), start);
                put(configuration.endAddress(), end);
            }
        };

        GhiHornifierBuilder hornBuilder = new GhiHornifierBuilder(PathAnalyzerController.NAME)
                .withDecompiler(new GhiHornSimpleDecompiler())
                .withApiDatabase(apiDb)
                .withEntryPoint(entry)
                .withParameters(parameters);

        GhiHornifier hornifier = hornBuilder.build();

        if (!hornifier.verifyConfiguration()) {
            throw new Exception("Cannot configure PathAnalyzer");
        }
        return new Pair<>(listener, hornifier);
    }

    /**
     * Setup a PathAnalyzer hornifier
     * 
     * @param start
     * @param end
     * @return A tool pair consisting of a front and back end
     */
    public Pair<GhiHornEventListener, GhiHornifier> setUpPathAnalyzer(final Address entry, final Address start,
            final Address end)
            throws Exception {

        return setUpPathAnalyzer(entry, start, end, new DummyApiDatabase());

    }

    /**
     * Setup a PathAnalyzer hornifier
     * 
     * @param start
     * @param end
     * @return A tool pair consisting of a front and back end
     */
    public Pair<GhiHornEventListener, GhiHornifier> setUpApiAnalyzer(final Address entry, final ApiSignature sig)
            throws Exception {

        return setUpApiAnalyzer(entry, sig, new DummyApiDatabase());

    }

    /**
     * Setup a ApiAnalyzer hornifier
     * 
     * @param sig the signature to search for
     * @param goal
     * @return A tool pair consisting of a front and back end
     */
    public Pair<GhiHornEventListener, GhiHornifier> setUpApiAnalyzer(final Address entry, final ApiSignature sig,
            ApiDatabase apiDb)
            throws Exception {

        GhiHornEventListener controller = new GhiHornEventListener();
        final ApiAnalyzerConfig configuration =
                ApiAnalyzerController.class.getAnnotation(ApiAnalyzerConfig.class);

        controller.registerCommandEvent(configuration.events().resultUpdate(),
                GhiHornCommandEvent.ResultReady);
        controller.registerCommandEvent(configuration.events().statusUpdate(),
                GhiHornCommandEvent.StatusMessage);
        controller.registerCommandEvent(configuration.events().completeUpdate(),
                GhiHornCommandEvent.Completed);
        controller.registerCommandEvent(configuration.events().cancelUpdate(),
                GhiHornCommandEvent.Cancelled);

        Map<String, Object> parameters = new HashMap<>() {
            {
                put(configuration.signatures(), sig);
            }
        };
        GhiHornifierBuilder hornBuilder = new GhiHornifierBuilder(ApiAnalyzerController.NAME)
                .withDecompiler(new GhiHornSimpleDecompiler())
                .withApiDatabase(apiDb)
                .withEntryPoint(entry)
                .withParameters(parameters);

        GhiHornifier hornifier = hornBuilder.build();
        if (!hornifier.verifyConfiguration()) {
            throw new Exception("Cannot configure ApiAnalyzer");
        }
        return new Pair<>(controller, hornifier);
    }

    /**
     * 
     * @param sigStr
     * @return
     */
    public List<ApiSignature> loadSigs(String sigStr) {
        List<ApiSignature> signatures = new ArrayList<>();

        try (Reader reader = new StringReader(sigStr)) {
            Gson gson = new Gson();
            SignaturesType sigs = gson.fromJson(reader, SignaturesType.class);

            for (SignatureEntry sig : sigs.signatures) {

                List<ApiFunction> apiFuncList = new ArrayList<>();
                sig.getSequence().forEach(s -> apiFuncList
                        .add(new ApiFunction(s.getApiName(), s.getApiParameters(),
                                s.getApiRetnValue())));

                signatures.add(new ApiSignature(sig.getName(), sig.getDescription(), apiFuncList));
            }
            return signatures;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new ArrayList<>();
    }

    public void printProgramInstuctions(final Program p) {
        p.getListing().getInstructions(true)
                .forEach(i -> Msg.info(this, i.getAddress() + ": " + i.toString()));
    }
}
