package kaiju.tools.ghihorn;

import com.microsoft.z3.Version;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.builder.ActionBuilder;
import generic.jar.ResourceFile;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GhidraScriptService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import kaiju.common.*;
import kaiju.common.KaijuLogger;
import kaiju.common.KaijuPluginPackage;
import kaiju.tools.ghihorn.api.ApiDatabase;
import kaiju.tools.ghihorn.api.GhiHornApiDatabase;
import kaiju.tools.ghihorn.cmd.GhiHornCommand;
import kaiju.tools.ghihorn.decompiler.GhiHornParallelDecompiler;
import kaiju.tools.ghihorn.decompiler.GhiHornSimpleDecompiler;
import kaiju.tools.ghihorn.display.GhiHornController;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerController;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerController;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = KaijuPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Analyze horn clauses",
	description = "Generate and analyze horn clauses using z3 and Ghidra.",
    servicesRequired = {GoToService.class, 
                        ColorizingService.class,       
                        GhidraScriptService.class, 
                        ProgramManager.class},
	eventsProduced = { ProgramSelectionPluginEvent.class }	
)
//@formatter:on
/**
 * The main plugin class
 */
public class GhiHornPlugin extends ProgramPlugin implements AutoAnalysisManagerListener {

    public static final String PLUGIN_NAME = "GhiHorn";

    // Universal configuration settings used by all tools
    public static final String HORNIFIER_NAME = "GH:Hornifier";
    
    private static boolean z3LibsFound;

    static {
        z3LibsFound = false;
        try {
            ResourceFile z3osDir = Application.getModuleSubDirectory("kaiju",
                "os/" + Platform.CURRENT_PLATFORM.getDirectoryName());
            String OS_DIR = z3osDir.getAbsolutePath() + "/";
            
            ResourceFile z3libDir = Application.getModuleSubDirectory("kaiju", "lib/");
            String LIB_DIR = z3libDir.getAbsolutePath() + "/";
            
            KaijuNativeLibraryLoaderUtil.addLibsToJavaLibraryPath(OS_DIR);
            
            System.load(OS_DIR + "libz3" + Platform.CURRENT_PLATFORM.getLibraryExtension());
            System.load(OS_DIR + "libz3java" + Platform.CURRENT_PLATFORM.getLibraryExtension());
            String z3status = "Z3 version: " + Version.getFullVersion();
            z3LibsFound = true;
        } catch (FileNotFoundException fnfe) {
            // TODO
        } catch (IOException ioe) {
            // TODO
        } catch (UnsatisfiedLinkError ule) {
            // TODO
        }
    }

    // The API service
    private GhiHornApiDatabase apiDatabase;

    private TaskMonitor monitor;

    // This is the base component provider for the plugin
    private GhiHornProvider provider;

    private DockingAction ghihornAction;

    /**
     * Plugin constructor
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public GhiHornPlugin(final PluginTool tool) {

        super(tool, true, true);

        monitor = new TaskMonitorAdapter(true);

        Msg.info(this, PLUGIN_NAME + " plugin loaded.");
    }


    /**
     * Execute the plugin by launching a background command
     * 
     * @param model
     */
    public void execute(GhiHornCommand cmd) throws RuntimeException {
        this.tool.executeBackgroundCommand(cmd, currentProgram);
    }

    public void cancel() {
        if (this.tool != null) {
            this.tool.terminateBackgroundCommands(false);
        }
    }

    @Override
    public boolean goTo(Address addr) {
        return super.goTo(addr);
    }

    @Override
    protected void dispose() {
        if (apiDatabase != null) {
            apiDatabase.freeApiLibraries();
        }
    }

    /**
     * Called when a new program is activated
     */
    @Override
    protected void programActivated(final Program program) {

        super.programActivated(program);

        // Rerun auto analysis to remove/fix badness, such as non-returning
        // functions
        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
        if (!aam.isAnalyzing()) {
            Msg.info(this, "Rerunning auto-analysis");
            aam.reAnalyzeAll(program.getMemory());
        }

        aam.addListener(this);

        // Install a new action to show the GhiHorn interface
        if (!SystemUtilities.isInHeadlessMode()) {

            List<GhiHornController> controllers = Arrays.asList(new GhiHornController[] {
                    new PathAnalyzerController(this), new ApiAnalyzerController(this)});

            this.provider = new GhiHornProvider(tool, this, controllers);

            this.ghihornAction = new ActionBuilder("Open GhiHorn", getName())
                    .supportsDefaultToolContext(true)
                    .menuPath("&Kaiju", "GhiHorn")
                    .onAction(c -> provider.setVisible(true))
                    .menuIcon(null)
                    .keyBinding("ctrl G")
                    .enabled(false)
                    .buildAndInstall(tool);
        } else {
            Msg.info(this, "Running in headless mode, use the GhiHorn script!");
        }

        if (!SystemUtilities.isInHeadlessMode()) {
            this.apiDatabase = new GhiHornApiDatabase(new GhiHornSimpleDecompiler());
        } else {
            this.apiDatabase = new GhiHornApiDatabase(new GhiHornParallelDecompiler(this.tool));
        }

        Msg.info(this, PLUGIN_NAME + " activated");
    }

    /**
     * @return TaskMonitor return the monitor
     */
    public TaskMonitor getTaskMonitor() {
        return monitor;
    }

    /**
     * @return ApiAnalyzerProvider return the provider
     */
    public GhiHornProvider getProvider() {
        return provider;
    }

    public ProgramSelection getCurrentSelection() {
        return getCurrentSelection();
    }

    public ProgramSelection getCurrentHighlight() {
        return getCurrentHighlight();
    }

    /**
     * @param provider the provider to set
     */
    public void setProvider(GhiHornProvider provider) {
        this.provider = provider;
    }

    public ApiDatabase getApiDatabase() {
        return this.apiDatabase;
    }


    @Override
    public void analysisEnded(AutoAnalysisManager manager) {

        List<Address> entryPoints = new ArrayList<>();
        AddressIterator ai = this.currentProgram.getSymbolTable().getExternalEntryPointIterator();

        while (ai.hasNext()) {
            Address extAddr = ai.next();
            Function entryFunc = this.currentProgram.getFunctionManager().getFunctionAt(extAddr);
            if (entryFunc != null) {

                // The name "entry" is special in Ghidra
                if (entryFunc.getName().equals("entry")) {
                    entryPoints.add(0, entryFunc.getEntryPoint());
                } else {
                    entryPoints.add(entryFunc.getEntryPoint());
                }
            }
        }

        provider.setEntryPoints(entryPoints);

        if (z3LibsFound) {
            ghihornAction.setEnabled(true);
        } else {
            ghihornAction.setMenuBarData(new MenuData(new String[]{"&Kaiju", "GhiHorn is missing Z3"}));
        }
    }
}
