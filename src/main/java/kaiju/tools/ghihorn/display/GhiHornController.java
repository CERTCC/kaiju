package kaiju.tools.ghihorn.display;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyChangeEvent;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.border.BevelBorder;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import com.google.common.base.VerifyException;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.GhiHornPlugin;
import kaiju.tools.ghihorn.GhiHornifierBuilder;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.format.GhiHornOutputFormatter;
import kaiju.tools.ghihorn.cmd.GhiHornCommand;
import kaiju.tools.ghihorn.cmd.GhiHornCommandListener;
import kaiju.tools.ghihorn.decompiler.GhiHornParallelDecompiler;
import kaiju.tools.ghihorn.display.graph.GhiHornAnswerGraphComponent;
import kaiju.tools.ghihorn.hornifer.GhiHornCommandEvent;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;
import kaiju.tools.ghihorn.z3.GhiHornZ3Parameters;

/**
 * Common properties for Horn displays
 */
public abstract class GhiHornController implements GhiHornCommandListener {

    protected final GhiHornPlugin plugin;
    protected Address entryPointAddress;
    private GhiHornAnswer currentResult;
    private final String name;
    private Map<GhiHornCommandEvent, String> eventConfig;
    private GhiHornZ3Parameters z3Params;

    // The IDs for properties all displays must handle
    protected String updateMessageID;
    protected String terminateMessageID;
    protected String resultMessageID;
    protected Set<GhiHornCommand> cmdList;

    protected GhiHornDisplaySettings displaySettings;

    protected GhiHornController(final String n, final GhiHornPlugin p) {

        this.name = n;
        this.plugin = p;
        this.displaySettings = new GhiHornDisplaySettings();
        this.eventConfig = new HashMap<>();
        this.cmdList = ConcurrentHashMap.newKeySet();
        this.entryPointAddress = Address.NO_ADDRESS;

        // Initialize specific tools
        initialize();
    }

    @Override
    public Map<GhiHornCommandEvent, String> getCommandEvents() {
        return this.eventConfig;
    }

    @Override
    public void registerCommandEvent(final String id, final GhiHornCommandEvent evt) {
        eventConfig.put(evt, id);
    }

    /**
     * @param displaySettings the displaySettings to set
     */
    public void setDisplaySettings(GhiHornDisplaySettings displaySettings) {
        this.displaySettings = displaySettings;
    }

    public String getName() {
        return name;
    }

    /**
     * Receive events from the ApiAnalyzer commands, either log or output
     */
    @Override
    public void propertyChange(PropertyChangeEvent evt) {

        final String propName = evt.getPropertyName();

        if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.StatusMessage))) {
            String update = (String) evt.getNewValue();
            status(update);

        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.Completed))) {

            GhiHornCommand endedCmd = (GhiHornCommand) evt.getNewValue();
            cmdList.remove(endedCmd);

            // If there are no further commands to process, then terminate
            if (cmdList.isEmpty()) {
                this.plugin.getProvider().endAnalysis(false);
                status(getControllerName() + " completed.");
            }
        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.Cancelled))) {

            GhiHornCommand endedCmd = (GhiHornCommand) evt.getNewValue();
            cmdList.remove(endedCmd);

            // If there are no further commands to process, then terminate
            if (cmdList.isEmpty()) {
                this.plugin.getProvider().endAnalysis(true);
                var tool = this.plugin.getTool();
                if (tool != null) {
                    tool.cancelCurrentTask();
                }
                status(getControllerName() + " completed.");
            }

        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornCommandEvent.ResultReady))) {

            this.currentResult = (GhiHornAnswer) evt.getNewValue();
            result(currentResult);

        } else {
            Msg.info(this, "Unknown event received: " + propName);
        }
    }

    /**
     * Present the results as a graph
     * 
     * @param newGraph
     * @param mon
     * @return
     */
    protected JPanel installAnswerAsGraph(final GhiHornAnswer result) throws Exception {
        GhiHornAnswerGraphComponent graph =
                new GhiHornAnswerGraphComponent(plugin, result.answerGraph);

        if (displaySettings == null) {
            displaySettings = new GhiHornDisplaySettings();
        }

        graph.build(displaySettings);
        return graph.getComponent();
    }

    /**
     * Install the result as text
     * 
     * @param result
     * @return
     * @throws Exception
     */
    protected JPanel installResultsAsText(final GhiHornAnswer result) throws Exception {

        JTextPane textPane = new JTextPane();
        SimpleAttributeSet attributeSet = new SimpleAttributeSet();

        Font font = new Font("Monospaced", Font.BOLD, 12);
        textPane.setFont(font);

        if (result.status == GhiHornFixedpointStatus.Satisfiable) {
            StyleConstants.setForeground(attributeSet, Color.blue);
        } else if (result.status == GhiHornFixedpointStatus.Unsatisfiable) {
            StyleConstants.setForeground(attributeSet, Color.red);
        }

        textPane.setCharacterAttributes(attributeSet, true);

        if (result.answerGraph != null) {
            String graphTxt =
                    result.answerGraph.format(GhiHornOutputFormatter.create(displaySettings));
            textPane.setText(graphTxt);
        }
        return new JPanel(new BorderLayout()) {
            {
                setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
                add(new JScrollPane(textPane), BorderLayout.CENTER);
            }
        };
    }

    public void refresh() {
        result(currentResult);
    }

    public boolean executeCommands() throws Exception {

        reset();

        List<Map<String, Object>> cmdParametersList = getCommandParameters();

        final GhiHornParallelDecompiler parallelDecompiler =
                new GhiHornParallelDecompiler(this.plugin.getTool());

        for (Map<String, Object> parameters : cmdParametersList) {
            try {

                GhiHornifierBuilder hornBuilder = new GhiHornifierBuilder(getName())
                        .withDecompiler(parallelDecompiler)
                        .withApiDatabase(plugin.getApiDatabase())
                        .withEntryPoint(entryPointAddress)
                        .withZ3Params(z3Params)
                        .withParameters(parameters);

                GhiHornifier hornifier = hornBuilder.build();

                GhiHornCommand cmd = new GhiHornCommand(name, hornifier);

                cmd.addCommandListener(this);

                // Each command gets it's own hornifier to simplify threading issues
                plugin.execute(cmd);

                cmdList.add(cmd);

            } catch (VerifyException ve) {
                status("Improperly configured command");
                return false;

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // True if any commands are executing
        return !cmdList.isEmpty();

    }

    public void setEntryPoint(Address entryAddress) {
        this.entryPointAddress = entryAddress;
    }

    public void addZ3Parameters(GhiHornZ3Parameters z3Params) {

        if (z3Params != null) {
            this.z3Params = z3Params;
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    ////
    //// The API that specifc tools must implement
    ////
    ///////////////////////////////////////////////////////////////////////////////////////////////

    public abstract void initialize();

    public abstract List<Map<String, Object>> getCommandParameters() throws Exception;

    public abstract void enable();

    public abstract void disable();

    public abstract void result(GhiHornAnswer result);

    public abstract void status(String message);

    public abstract List<GhiHornAnswer> getResults(boolean includeErrors);

    public abstract void reset();

    public abstract JComponent getMainComponent();

    public abstract String getControllerName();

    public abstract GhiHornifier getHornifiier();
}
