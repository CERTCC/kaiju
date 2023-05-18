package kaiju.tools.ghihorn;

import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.NoClassDefFoundError;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.BevelBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import com.microsoft.z3.Version;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import docking.WindowPosition;
import docking.widgets.OkDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import generic.jar.GClassLoader;
import generic.jar.ResourceFile;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.LocationMemento;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.gotoquery.DefaultNavigatableLocationMemento;
import ghidra.app.script.AskDialog;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.framework.Application;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.Platform;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.common.*;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettingBuilder;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings.SettingVariables;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.api.GhiHornApiDatabase;
import kaiju.tools.ghihorn.display.GhiHornController;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.hornifer.horn.HornFunctionInstance;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;
import kaiju.tools.ghihorn.z3.GhiHornZ3Parameters;

/**
 * Main headed UI for GhiHorn
 */
public class GhiHornProvider extends ComponentProviderAdapter implements Navigatable {

    private static boolean z3LibsFound;

    private final GhiHornPlugin plugin;
    private final DateTimeFormatter dateFormatter;
    private final GhiHornZ3Parameters z3Params;
    private JTabbedPane tabbedPane;
    private Map<Integer, GhiHornController> controllerUIMap;
    private JPanel mainPanel;
    private JLabel statusLabel;
    private GhidraComboBox<String> entryComboBox;
    private JButton analyzeButton, saveToFileButton, clearHighlightButton, z3ParamsButton;
    private JCheckBox showGlobalVarsCheckBox, showLocalVarsCheckBox, hideTempVarsCheckBox,
            hideExternalFuncsCheckbox;
    private List<GhiHornController> controllers;
    private Instant startInstant;

    // Utility class to detect changes to settings
    private class DisplaySettingsListener implements DocumentListener {
        boolean isChanged = false;

        @Override
        public void insertUpdate(DocumentEvent e) {
            isChanged = true;
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            isChanged = true;
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            isChanged = true;
        }
    }

    /**
     * Create a new GUI for the plugin
     * 
     * @param tool
     * @param plugin
     */
    public GhiHornProvider(final PluginTool tool, final ProgramPlugin plugin,
            List<GhiHornController> displays) {

        super(tool, GhiHornPlugin.PLUGIN_NAME, plugin.getName(), ProgramActionContext.class);

        this.plugin = (GhiHornPlugin) plugin;
        this.controllers = displays;
        this.z3LibsFound = false;
        plugin.getTool().getService(ColorizingService.class);

        dateFormatter =
                DateTimeFormatter.ofLocalizedDateTime(FormatStyle.FULL).withLocale(Locale.US)
                        .withZone(ZoneId.systemDefault());

        z3Params = new GhiHornZ3Parameters();
        z3Params.put("fp.engine", "spacer");
        z3Params.put("fp.xform.inline_eager", false);
        z3Params.put("fp.xform.slice", false);
        z3Params.put("fp.xform.inline_linear", false);
        z3Params.put("fp.xform.subsumption_checker", false);
        z3Params.put("fp.datalog.generate_explanations", true);

        buildMainPanel();

        setDefaultWindowPosition(WindowPosition.BOTTOM);
    }

    /**
     * 
     * @return
     */
    private JPanel buildAnalysisControlPanel() {

        final JPanel controlPanel = new JPanel();
        analyzeButton = new JButton("Analyze");
        JLabel apiDbLabel = new JLabel();
        try {
            ResourceFile apidbPath =
                    Application.getModuleDataSubDirectory(GhiHornApiDatabase.DEFAULT_API_DIRECTORY);
            apiDbLabel.setText("API database: \"" + apidbPath + "\"");
        } catch (IOException x) {
            apiDbLabel.setText("Unable to load API databse");
        }
        saveToFileButton = new JButton("Save Fixed Point");
        saveToFileButton.setEnabled(false);

        clearHighlightButton = new JButton("Clear Highlights");
        clearHighlightButton
                .addActionListener(e -> plugin.getProvider()
                        .setHighlight(new ProgramSelection(new AddressSet())));

        clearHighlightButton.setEnabled(false);

        z3ParamsButton = new JButton("Z3 Parameters");
        z3ParamsButton.addActionListener(e -> {

            final JPanel z3Panel = new JPanel(new GridLayout(2, 1));
            final JLabel directions = new JLabel(
                    "Enter Z3 parameters using the form \"Parameter=Value\" (one per line)");
            z3Panel.add(directions);

            final JTextArea textArea = new JTextArea("");
            textArea.setColumns(50);
            textArea.setLineWrap(false);
            textArea.setEditable(true);

            textArea.setWrapStyleWord(true);

            final StringBuffer z3ParamSb = new StringBuffer();
            for (Map.Entry<String, Object> z3p : z3Params.entrySet()) {
                textArea.append(
                        z3ParamSb.append(z3p.getKey()).append("=").append(z3p.getValue())
                                .append("\n").toString());
            }
            textArea.setText(z3ParamSb.toString());

            textArea.setSize(textArea.getPreferredSize().width, 1);

            DisplaySettingsListener sl = new DisplaySettingsListener();
            textArea.getDocument().addDocumentListener(sl);

            z3Panel.add(new JScrollPane(textArea) {
                {
                    setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
                    setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
                }
            });

            JOptionPane.showMessageDialog(
                    controlPanel, z3Panel, "Z3 Parameters", JOptionPane.INFORMATION_MESSAGE);

            if (sl.isChanged) {
                // parameters have changed
                parseZ3Parameters(textArea.getText());
            }
        });
        z3ParamsButton.setEnabled(true);

        entryComboBox = new GhidraComboBox<>();
        entryComboBox.setEditable(true);

        entryComboBox.addItemListener(i -> {
            String selectedAddr = (String) i.getItem();
            Address entryAddr =
                    plugin.getCurrentProgram().getAddressFactory().getAddress(selectedAddr);
            controllers.forEach(c -> c.setEntryPoint(entryAddr));
        });

        GridBagLayout gbLayout = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        controlPanel.setLayout(gbLayout);

        JPanel buttonPanel = new JPanel(new GridLayout(1, 4));
        buttonPanel.setBorder(BorderFactory.createTitledBorder("Control"));
        buttonPanel.add(analyzeButton);
        buttonPanel.add(new JPanel(new FlowLayout(FlowLayout.LEADING)) {
            {
                add(new JLabel("Program entry point:"));
                add(entryComboBox);
            }
        });
        buttonPanel.add(z3ParamsButton);
        buttonPanel.add(saveToFileButton);
        buttonPanel.add(clearHighlightButton);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 10;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 1;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(0, 0, 0, 1);
        gbLayout.setConstraints(buttonPanel, gbc);
        controlPanel.add(buttonPanel);

        final JPanel optPanel = new JPanel(new GridLayout(1, 4));
        optPanel.setBorder(BorderFactory.createTitledBorder("Display Options"));
        showGlobalVarsCheckBox = new JCheckBox(SettingVariables.ShowGlobalVars.description());
        showLocalVarsCheckBox = new JCheckBox(SettingVariables.ShowLocalVars.description());
        hideTempVarsCheckBox = new JCheckBox(SettingVariables.HideTempVars.description());
        hideExternalFuncsCheckbox =
                new JCheckBox(SettingVariables.HideExternalFunctions.description());

        final DisplaySettingsHandler dispChangeHandler = new DisplaySettingsHandler();
        showGlobalVarsCheckBox.addItemListener(dispChangeHandler);
        showLocalVarsCheckBox.addItemListener(dispChangeHandler);
        hideTempVarsCheckBox.addItemListener(dispChangeHandler);
        hideExternalFuncsCheckbox.addItemListener(dispChangeHandler);

        showGlobalVarsCheckBox.setSelected(true);
        showLocalVarsCheckBox.setSelected(true);
        hideTempVarsCheckBox.setSelected(true);
        hideExternalFuncsCheckbox.setSelected(true);

        optPanel.add(showGlobalVarsCheckBox);
        optPanel.add(showLocalVarsCheckBox);
        optPanel.add(hideTempVarsCheckBox);
        optPanel.add(hideExternalFuncsCheckbox);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 20;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 1;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbLayout.setConstraints(optPanel, gbc);
        controlPanel.add(optPanel);

        statusLabel =
                new JLabel("Ready to analyze");

        JLabel z3VerLabel = new JLabel("");
        try {
            z3VerLabel.setText("Z3 version: " + Version.getFullVersion());
            z3LibsFound = true;
        } catch (NoClassDefFoundError nce) {
            // this happens when java can't find the libraries
            z3VerLabel.setText("Warning: NoClassDefFoundError while loading Z3, GhiHorn will not run.");
        } catch (UnsatisfiedLinkError e) {
            z3VerLabel.setText("Warning: Z3 libraries not loaded, GhiHorn will not run.");
            // TODO: Java didn't automatically find the libraries.
        }

        JPanel statusPanel = new JPanel(new GridLayout(3, 1));
        statusPanel.setBorder(BorderFactory.createTitledBorder("Status"));
        statusPanel.add(statusLabel);
        statusPanel.add(z3VerLabel);
        statusPanel.add(apiDbLabel);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 1;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.SOUTHWEST;
        gbLayout.setConstraints(statusPanel, gbc);
        controlPanel.add(statusPanel);

        analyzeButton.addActionListener(e -> {

            // clear the highlight
            plugin.getProvider().setHighlight(new ProgramSelection(new AddressSet()));

            if (!z3LibsFound) {
                OkDialog.showError("Z3 Not Found", "Cannot use GhiHorn without Z3");
                return;
            }

            try {
                GhiHornController controller = getActiveController();
                if (!z3Params.isEmpty()) {
                    controller.addZ3Parameters(z3Params);
                    final StringBuffer z3StrBuf =
                            new StringBuffer("Executing with Z3 parameters:\n");

                    for (Map.Entry<String, Object> z3p : z3Params.entrySet()) {

                        z3StrBuf.append("* ")
                                .append(z3p.getKey())
                                .append("=")
                                .append(z3p.getValue())
                                .append("\n")
                                .toString();
                    }

                    updateStatus(z3StrBuf.toString());
                }

                String entryAddr = (String) entryComboBox.getSelectedItem();
                Address epAddress = plugin.getCurrentProgram()
                        .getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(entryAddr);

                controller.setEntryPoint(epAddress);

                if (controller.executeCommands()) {
                    beginAnalysis();

                } else {
                    updateStatus("Execution was aborted");
                }

            } catch (AddressFormatException | NullPointerException e2) {
                updateStatus("Invalid start/end address specified");
            } catch (Exception x) {
                x.printStackTrace();
                OkDialog.showError("Plugin execution error", x.getMessage());
            }
            saveToFileButton.setEnabled(false);
        });

        saveToFileButton.addActionListener(e -> {

            GhiHornController selectedTool = getCurrentFrontEnd();
            final List<GhiHornAnswer> results = selectedTool.getResults(false);

            GhiHornAnswer result =
                    askChoice("Select results", "Select result to save:", results, null);
            if (result == null) {
                return;
            }
            if (result.status == GhiHornFixedpointStatus.Error) {
                OkDialog.showError("Save fixed point", "You must select a valid result to save");
                return;
            }

            final GhidraFileChooser chooser = new GhidraFileChooser(null);
            final AtomicReference<File> selectedFileRef = new AtomicReference<>();
            final Runnable r = () -> {
                chooser.setTitle("Save Fixedpoint to file");
                chooser.setSelectedFile(selectedFileRef.get());
                chooser.setApproveButtonText("Select");
                chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
                selectedFileRef.set(chooser.getSelectedFile());
            };
            SystemUtilities.runSwingNow(r);

            final File file = selectedFileRef.get();

            if (file.exists()) {
                try {
                    Files.delete(Path.of(file.toURI()));
                    if (file.createNewFile() == false) {
                        OkDialog.showError("Saved fixed point",
                                "Could not create file " + file.getName());
                        return;
                    }
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }

            // Write the fixed point to a file
            synchronized (result) {
                try (FileWriter writer = new FileWriter(file)) {
                    writer.write(
                            "(set-logic HORN)\n(set-option :fp.engine spacer)\n(set-option :fp.xform.inline_eager false)\n(set-option :fp.xform.slice false)\n(set-option :fp.xform.inline_linear false)(set-option :fp.xform.subsumption_checker false)\n\n");
                    writer.write(result.fxString);
                    writer.write("\n\n(query goal :print-certificate true)");

                    writer.flush();
                    writer.close();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
            }

            OkDialog.show("Saved fixed point", "SMT saved to " + file.getName());

        });

        return controlPanel;
    }

    public GhiHornController getActiveController() {
        return this.controllerUIMap.get(tabbedPane.getSelectedIndex());
    }

    /**
     * Fetch the current front end
     * 
     * @return
     */
    public GhiHornController getCurrentFrontEnd() {
        if (tabbedPane != null) {
            int selectedIndex = tabbedPane.getSelectedIndex();
            if (selectedIndex != -1) {
                return this.controllerUIMap.get(selectedIndex);
            }
        }
        return null;
    }

    private void parseZ3Parameters(String newParamText) {

        Map<String, Object> newParams = new HashMap<>();

        String[] lines = newParamText.split(System.getProperty("line.separator"));
        for (String line : lines) {
            if (line.length() == 0)
                continue;
            String[] paramEntry = line.split("=");
            if (paramEntry.length != 2)
                continue;

            String name = paramEntry[0];
            String value = paramEntry[1];

            if (value.length() == 0) {
                continue;
            }

            if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false")) {
                newParams.put(name, Boolean.parseBoolean(value));
            } else if (NumberUtils.isCreatable(newParamText)) {
                newParams.put(name, Integer.parseInt(value));
            } else {
                newParams.put(name, value);
            }
        }
        if (!newParams.isEmpty()) {
            z3Params.clear();
            z3Params.putAll(newParams);
        }
    }

    /**
     * Handle the display
     */
    private class DisplaySettingsHandler implements ItemListener {
        @Override
        public void itemStateChanged(ItemEvent e) {
            if (tabbedPane != null) {
                updateDisplaySettings();
            }
        }
    }

    /**
     * Update display settings
     */
    private void updateDisplaySettings() {

        GhiHornDisplaySettings displaySettings = (new GhiHornDisplaySettingBuilder())
                .showGlobalVariables(showGlobalVarsCheckBox.isSelected())
                .showLocalVariables(showLocalVarsCheckBox.isSelected())
                .hideTempVariables(hideTempVarsCheckBox.isSelected())
                .hideExternalFuncs(hideExternalFuncsCheckbox.isSelected())
                .build();

        final GhiHornController controller = getActiveController();

        controller.setDisplaySettings(displaySettings);

        controller.refresh();
    }

    /**
     * Highlight the answer when a result is selected
     * 
     * @param answer
     */
    public void highlightAnswer(final GhiHornAnswer answer) {

        plugin.goTo(answer.arguments.getEntryAsAddress());

        final AddressSet addrSet = new AddressSet();
        for (GhiHornAnswerGraphVertex vtx : answer.answerGraph.getVertices()) {
            GhiHornAnswerAttributes attrs = vtx.getAttributes();
            HornElement elm = attrs.getHornElement();
            final ProgramLocation loc = elm.getLocator();
            if (loc == null) {
                continue;
            }
            final SimpleBlockModel basicBlockModel = new SimpleBlockModel(loc.getProgram());
            try {
                CodeBlock block = basicBlockModel.getFirstCodeBlockContaining(loc.getAddress(),
                        TaskMonitor.DUMMY);
                if (block != null) {
                    addrSet.add(block.getMinAddress(), block.getMaxAddress());
                } else {

                    // Fall back on the call address

                    HornProgram hornProg = answer.answerGraph.getHornProgram();

                    HornFunctionInstance instance =
                            hornProg.getInstanceByID(elm.getInstanceId()).get();

                    Address xrefAddr = instance.getXrefAddress();
                    block = basicBlockModel.getFirstCodeBlockContaining(xrefAddr,
                            TaskMonitor.DUMMY);
                    if (block != null) {
                        addrSet.add(block.getMinAddress(), block.getMaxAddress());
                    }
                }
            } catch (CancelledException e) {
                /* Should not happen */ }
        }

        ProgramSelection selection = new ProgramSelection(addrSet);
        plugin.getProvider().setHighlight(selection);

    }

    /**
     * Build the main panel
     * 
     * @return
     */
    private JPanel buildMainPanel() {

        this.mainPanel = new JPanel(new GridBagLayout());

        mainPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
        final GridBagConstraints gbConstraints = new GridBagConstraints();
        mainPanel.setLayout(new GridBagLayout());

        final JPanel analysisControlPanel = buildAnalysisControlPanel();

        gbConstraints.gridx = 1;
        gbConstraints.gridy = 10;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.NONE;
        gbConstraints.weightx = 1;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.SOUTHWEST;
        mainPanel.add(analysisControlPanel, gbConstraints);

        this.controllerUIMap = new HashMap<>();

        this.tabbedPane = new JTabbedPane();
        for (int i = 0; i < controllers.size(); i++) {
            GhiHornController dsp = controllers.get(i);
            tabbedPane.addTab(dsp.getName(), dsp.getMainComponent());
            controllerUIMap.put(i, dsp);
        }

        this.tabbedPane.setSelectedIndex(0);

        gbConstraints.gridx = 1;
        gbConstraints.gridy = 1;
        gbConstraints.gridwidth = GridBagConstraints.REMAINDER;
        gbConstraints.gridheight = 5;
        gbConstraints.fill = GridBagConstraints.BOTH;
        gbConstraints.weightx = 1;
        gbConstraints.weighty = 1;
        gbConstraints.anchor = GridBagConstraints.NORTH;
        gbConstraints.insets.right = 10;
        mainPanel.add(tabbedPane, gbConstraints);

        return mainPanel;
    }

    /**
     * Method to ask a user to select from an array of choices (copied from GhidraScript).
     * 
     * @param title popup window title
     * @param message message to display during choice
     * @param choices array of choices for the users
     * @param defaultValue the default value to select
     * @return the user's choice, or null
     * @throws CancelledException if the user cancels
     */
    public <T> T askChoice(String title, String message, List<T> choices, T defaultValue) {
        AskDialog<T> dialog =
                new AskDialog<>(null, title, message, AskDialog.STRING, choices, defaultValue);
        if (dialog.isCanceled()) {
            return null;
        }

        T s = dialog.getChoiceValue();
        return s;
    }

    public synchronized void beginAnalysis() {

        startInstant = Instant.now();
        statusLabel.setText("Analysis started at " + dateFormatter.format(startInstant));

        statusLabel.setForeground(Color.blue);

        z3ParamsButton.setEnabled(false);
        clearHighlightButton.setEnabled(false);
        analyzeButton.setEnabled(false);
    }

    /**
     * Update the output
     * 
     * @param output
     */
    public synchronized void endAnalysis(boolean isCancelled) {

        // GitHub bug #34, startInstant sometimes null?
        // TODO: do simple check, is there a better fix?
        // this wouldn't show proper duration if it was null
        if (startInstant == null) {
            startInstant = Instant.now();
        }
    
        long duration = Duration.between(startInstant, Instant.now()).toMillis();
        String durStr = DurationFormatUtils.formatDuration(duration, "HH'hrs' mm'mins' ss'sec'");

        if (!isCancelled) {

            statusLabel.setText("Analysis completed in " + durStr);
            statusLabel.setForeground(Color.black);

        } else {

            statusLabel.setText("Analysis cancelled after " + durStr);
            statusLabel.setForeground(Color.red);
        }

        saveToFileButton.setEnabled(true);
        clearHighlightButton.setEnabled(true);
        z3ParamsButton.setEnabled(true);
        analyzeButton.setEnabled(true);
    }

    /**
     * Update status window
     * 
     * @param statusUpdate
     */
    public void updateStatus(final String statusUpdate) {

        GhiHornController hornController = getActiveController();
        hornController.status(statusUpdate);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void enableAnalysis() {
        this.analyzeButton.setEnabled(true);
    }

    public void disableAnalysis() {
        this.analyzeButton.setEnabled(false);
    }

    @Override
    public boolean goTo(Program program, ProgramLocation location) {
        return this.goTo(program, location);

    }

    @Override
    public ProgramLocation getLocation() {
        return plugin.getProgramLocation();
    }

    @Override
    public Program getProgram() {
        return plugin.getCurrentProgram();
    }

    @Override
    public LocationMemento getMemento() {
        return new DefaultNavigatableLocationMemento(getProgram(), getLocation(), tool);

    }

    @Override
    public void setMemento(LocationMemento memento) {
        DefaultNavigatableLocationMemento defaultMemento =
                (DefaultNavigatableLocationMemento) memento;
        defaultMemento.setMementos();
    }

    @Override
    public Icon getNavigatableIcon() {
        return null;
    }

    @Override
    public boolean isConnected() {
        return true;
    }

    @Override
    public boolean supportsMarkers() {
        return isConnected();
    }

    @Override
    public void setSelection(ProgramSelection selection) {
        tool.firePluginEvent(new ProgramSelectionPluginEvent(getName(), selection, getProgram()));

    }

    @Override
    public void setHighlight(ProgramSelection highlight) {
        tool.firePluginEvent(new ProgramHighlightPluginEvent(getName(), highlight, getProgram()));
    }

    @Override
    public ProgramSelection getSelection() {
        return plugin.getCurrentSelection();
    }

    @Override
    public ProgramSelection getHighlight() {
        return plugin.getCurrentHighlight();
    }

    @Override
    public void addNavigatableListener(NavigatableRemovalListener listener) {
        // do nothing, default Navigatable never goes away
    }

    @Override
    public void removeNavigatableListener(NavigatableRemovalListener listener) {
        // do nothing, default Navigatable never goes away
    }

    @Override
    public boolean isDisposed() {
        return plugin.isDisposed();
    }

    @Override
    public boolean supportsHighlight() {
        return true;
    }

    @Override
    public void setHighlightProvider(ListingHighlightProvider highlightProvider, Program program) {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service != null) {
            service.setHighlightProvider(highlightProvider, program);
        }

    }

    @Override
    public void removeHighlightProvider(ListingHighlightProvider highlightProvider, Program program) {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service != null) {
            service.removeHighlightProvider(highlightProvider, program);
        }
    }

    // Uncommenting this introduces a dependency for Ghidra 10
    // @Override
    public String getTextSelection() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Set the selected entry points
     * 
     * @param entryPointList
     */
    public void setEntryPoints(List<Address> entryPointList) {

        if (!entryPointList.isEmpty()) {
            if (entryComboBox.getItemCount()>0) {
                entryComboBox.removeAllItems();
            }
            entryPointList.stream()
                    .map(f -> f.toString())                    
                    .forEach(entryComboBox::addItem);
            entryComboBox.setSelectedIndex(0);
            controllers.forEach(c -> c.setEntryPoint(entryPointList.get(0)));
        }
    }
}
