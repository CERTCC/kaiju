package kaiju.tools.ghihorn.hornifer.horn;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import ghidra.graph.GraphAlgorithms;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import kaiju.tools.ghihorn.cfg.HighCfg;
import kaiju.tools.ghihorn.cfg.HighCfgVertex;
import kaiju.tools.ghihorn.cfg.VertexAttributes;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.block.HornBlockProperty;
import kaiju.tools.ghihorn.hornifer.block.HornBlockProperty.Property;
import kaiju.tools.ghihorn.hornifer.block.HornRetnProperty;
import kaiju.tools.ghihorn.hornifer.edge.HornEdge;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;

public class HornFunction {

    private final Function function;
    private final Map<Address, HornBlock> hornBlocks;
    private final Set<HornEdge> hornEdges;
    private final Map<HornBlock, Set<HornEdge>> outEdges;
    private final Map<HornBlock, Set<HornEdge>> inEdges;
    private final Set<Address> callXrefsTo;
    private final Map<HornBlock, Set<HornVariable>> descendantVarsMap;
    private final Map<HornBlock, Set<HornBlock>> descendantBlkMap;
    private HighFunction highFunction;
    private HighCfg<Address, VertexAttributes> highCfg;
    private HornBlock entryBlock;
    private List<HornBlock> callBlocks;
    private List<HornBlock> retnBlocks;
    private List<HornVariable> parameters;
    private HornVariable resultVar;
    private Set<HornVariable> localVariables;
    private LiveHornVariables<HornBlock> liveVars;
    private String name;
    private boolean isImported;

    public HornFunction(HighFunction f) {
        this(f.getFunction());
        this.highFunction = f;
        this.highCfg = HighCfg.build(f);
    }

    /**
     * Create a new HornFunction from a Function
     * 
     * @param f
     */
    public HornFunction(final Function f) {

        this.function = f;
        this.highFunction = null;
        this.highCfg = null;
        this.hornBlocks = new HashMap<>();
        this.hornEdges = new HashSet<>();
        this.outEdges = new HashMap<>();
        this.inEdges = new HashMap<>();
        this.descendantVarsMap = new HashMap<>();
        this.descendantBlkMap = new HashMap<>();

        this.localVariables = new HashSet<>();
        this.parameters = new ArrayList<>();
        this.resultVar = null;

        // specific types of blocks in this function
        this.callBlocks = new ArrayList<>();
        this.retnBlocks = new ArrayList<>();
        this.entryBlock = null;
        //this.entryBlock = new HornBlock(this, new HighCfgVertex<Address, VertexAttributes>());
        this.liveVars = null;
        this.name = function.getName(true);

        final ReferenceManager refMgr = f.getProgram().getReferenceManager();
        final ReferenceIterator startIter = refMgr.getReferencesTo(function.getEntryPoint());

        callXrefsTo = StreamSupport.stream(startIter.spliterator(), false)
                .filter(r -> r.getReferenceType().isCall())
                .map(r -> r.getFromAddress()).collect(Collectors.toSet());
    }

    /**
     * @param parameters the parameters to set
     */
    public void addParameter(int ordinal, HornVariable parameter) {
        this.parameters.add(ordinal, parameter);
    }

    /**
     * Fetch the parameters in order
     * 
     * @return
     */
    public List<HornVariable> getParameters() {
        return this.parameters;
    }

    /**
     * @return the localVariables
     */
    public Set<HornVariable> getLocalVariables() {
        return this.localVariables;
    }


    /**
     * @param result the result to set
     */
    public void setResultVariable(HornVariable result) {
        this.resultVar = result;
    }

    /**
     * @return the result
     */
    public HornVariable getResult() {
        return resultVar;
    }

    /**
     * Add new xref
     * 
     * @param additionalXrefs
     */
    public void addXrefs(List<Address> additionalXrefs) {
        callXrefsTo.addAll(additionalXrefs);
    }

    /**
     * True if this function has an call XREF
     * 
     * @return true if called, false otherwise
     */
    public boolean isCalled() {
        return !callXrefsTo.isEmpty();
    }

    /**
     * Thunk functions are the basically the same as
     * 
     * @return true if a thunk, false otherwise
     */
    public boolean isThunk() {
        return this.highFunction != null && this.highFunction.getFunction().isThunk();
    }

    /**
     * A horn function is external if it has no CFG or high function
     * 
     * @return true if external
     */
    public boolean isExternal() {
        return this.highFunction == null || this.highCfg == null;
    }

    /**
     * A horn function is imported if it not in the current program
     * 
     * @return
     */
    public boolean isImported() {
        return this.isImported;
    }

    /**
     * @param isImported the isImported to set. An imported function is one that is loaded
     */
    public void setImported(boolean isImported) {
        this.isImported = isImported;
    }

    /**
     * Compute the live output variables
     * 
     * @param block
     * @param in
     * @return
     */
    private Set<HornVariable> computeLiveOut(HornBlock block,
            Map<HornBlock, Set<HornVariable>> in) {

        Set<HornVariable> out = new HashSet<>();

        // Exit blocks have all out params live at exit. Globals and
        // function-scoped variables are assumed live throughout their scope

        if (block.hasProperty(Property.Return)) {

            final HornRetnProperty retnProperty =
                    (HornRetnProperty) block.getProperty(Property.Return);

            out.add(retnProperty.getReturnValue());

        } else {

            // The problem with using direct successors is that there may be
            // live variables that aren't propogated sufficiently, especially
            // when loops are present.
            //
            // If you want better solving, then use the successor code below.
            // note that this will slow things down considerably
            //
            // for (var s : hornFunc.getHighCfg().successorListOf(block.getVertex())) {
            // HornBlock suc = hornFunc.getBlockByAddress(s.getLocator());
            // for (var suc : getDescendants(block)) {
            // if (!suc.equals(block)) {
            // out.addAll(in.get(suc));
            // }
            // }
            Set<HornBlock> descBlks = this.descendantBlkMap.get(block);
            if (descBlks != null) {
                descBlks.stream()
                        .filter(d -> !d.equals(block))
                        .forEach(d -> out.addAll(in.get(d)));
            } else {

                descBlks = getDescendantBlocks(block);
                descBlks.stream()
                        .filter(d -> !d.equals(block))
                        .forEach(d -> out.addAll(in.get(d)));

                this.descendantBlkMap.put(block, descBlks);
            }

            // Add all variable used in the current block.
            out.addAll(block.getUseVariables());

        }

        return out;
    }

    /**
     * @return the xrefsTo
     */
    public Set<Address> getCallXrefsTo() {
        return callXrefsTo;
    }

    /**
     * Return the set of live variable at the entry of each block. A variable is live between its
     * first and last use. Following the algorithm on p610 of the dragon book, 2nd ed. Inspired by
     * Jayhorn and Soot
     *
     * @return the computed live variables organized by block
     */
    public LiveHornVariables<HornBlock> computeLiveVariables() {

        if (this.liveVars != null) {
            return this.liveVars;
        }

        Collection<HornBlock> blocks = getBlocks();
        if (blocks.isEmpty()) {
            return null;
        }

        final Map<HornBlock, Set<HornVariable>> in = new HashMap<>();
        final Map<HornBlock, Set<HornVariable>> out = new HashMap<>();

        // cache these to save time
        Map<HornBlock, Set<HornVariable>> use = new HashMap<>();
        Map<HornBlock, Set<HornVariable>> def = new HashMap<>();

        // Start by initializing in to empty. The book does this separately for
        // exit and non exit blocks, but that's not necessary

        // which case we should actually recurse over all blocks!
        for (HornBlock b : getBlocks()) {
            in.put(b, new HashSet<HornVariable>());
            use.put(b, b.getUseVariables());
            def.put(b, b.getDefVariables());
        }

        boolean changed = false;

        do {
            changed = false;
            for (HornBlock b : getBlocks()) {

                out.put(b, computeLiveOut(b, in));

                Set<HornVariable> newIn = GhiHornifier.setUnion(use.get(b),
                        GhiHornifier.setMinus(out.get(b), def.get(b)));

                if (!newIn.equals(in.get(b))) {
                    changed = true;
                    in.put(b, newIn);
                }
            }
        } while (changed);

        // Removing nulls and constants here for simplicity's sake (although constants shouldn't be
        // included to begin with)

        in.values().forEach(s -> s.removeIf(elm -> elm == null || elm instanceof HornConstant));
        out.values().forEach(s -> s.removeIf(elm -> elm == null || elm instanceof HornConstant));

        this.liveVars = new LiveHornVariables<HornBlock>(in, out);

        return this.liveVars;
    }

    /**
     * Determine which variables must be passed through function call chains
     * 
     * @param blk the block
     * @return the variables maintained in the state
     */
    public Set<HornVariable> computeDescendantVariables(final HornBlock blk) {

        if (descendantVarsMap.containsKey(blk)) {
            return descendantVarsMap.get(blk);
        }
        Set<HornVariable> descendantVars = new HashSet<>();

        final LiveHornVariables<HornBlock> lv = computeLiveVariables();

        // Compute the descendants for each basic block, which are the blocks
        // that follow a given block, saving the live input variables as we go.

        getDescendantBlocks(blk).stream()
                .filter(b -> !b.equals(blk))
                .map(b -> lv.liveIn.get(b))
                .forEach(descendantVars::addAll);


        // The intersection of the descendant variables with the live out block variables are ones
        // that must be propogated forward.

        Set<HornVariable> blkLiveOutVars = lv.liveOut.get(blk);
        Set<HornVariable> stateVars = GhiHornifier.setIntersect(blkLiveOutVars, descendantVars);

        this.descendantVarsMap.put(blk, stateVars);
        return stateVars;
    }

    /**
     * Add a new horn block to this function
     * 
     * @param context
     * @param vertex
     */
    public void addHornBlock(final HornBlock newBlock) {

        // Index by address, which should be unique for each block
        this.hornBlocks.put(newBlock.getVertex().getLocator(), newBlock);

        // Save some special blocks
        if (newBlock.hasProperty(HornBlockProperty.Property.Entry)) {
            entryBlock = newBlock;
        }
        if (newBlock.hasProperty(HornBlockProperty.Property.Call)) {
            callBlocks.add(newBlock);
        }
        if (newBlock.hasProperty(HornBlockProperty.Property.Return)) {
            retnBlocks.add(newBlock);
        }

        this.localVariables.addAll(newBlock.getVariables());
    }

    public Function getFunction() {
        return this.function;
    }

    public HornBlock getEntryBlock() {
        return this.entryBlock;
    }

    public List<HornBlock> getCallBlocks() {
        return this.callBlocks;
    }

    public List<HornBlock> getReturnBlocks() {
        return this.retnBlocks;
    }

    public Collection<HornBlock> getBlocks() {
        return this.hornBlocks.values();
    }

    public HornBlock getBlockByAddress(final Address addr) {
        return this.hornBlocks.get(addr);
    }

    public HighCfg<Address, VertexAttributes> getHighCfg() {
        return this.highCfg;
    }

    public HighFunction getHighFunction() {
        return this.highFunction;
    }

    public boolean containsAddress(Address addr) {
        if (this.highFunction == null) {
            return false;
        }
        Function func = this.highFunction.getFunction();
        if (func == null) {
            return false;
        }
        return func.getBody().contains(addr);
    }

    public Address getEntry() {
        if (this.highCfg != null) {
            return this.highCfg.getEntryLocation();
        }
        return Address.NO_ADDRESS;
    }

    /**
     * Sometimes the name recovered in the function is not the name used for callers
     * 
     * @param name
     */
    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public void addHornEdge(HornEdge edge) {
        final HornBlock srcBlk = edge.getSource();
        if (this.outEdges.containsKey(srcBlk)) {
            this.outEdges.get(srcBlk).add(edge);
        } else {
            Set<HornEdge> outs = new HashSet<HornEdge>() {
                {
                    add(edge);
                }
            };
            this.outEdges.put(srcBlk, outs);
        }

        final HornBlock tgtBlk = edge.getTarget();
        if (this.inEdges.containsKey(tgtBlk)) {
            this.inEdges.get(tgtBlk).add(edge);
        } else {
            Set<HornEdge> ins = new HashSet<HornEdge>() {
                {
                    add(edge);
                }
            };
            this.inEdges.put(tgtBlk, ins);
        }
        this.hornEdges.add(edge);
    }

    public Set<HornEdge> getEdges() {
        return this.hornEdges;
    }

    public Set<HornEdge> getOutEdges(HornBlock blk) {
        return this.outEdges.get(blk);
    }

    public Set<HornEdge> getInEdges(HornBlock blk) {
        return this.inEdges.get(blk);
    }

    /**
     * Fectch imediate block successors
     * 
     * @param blk
     * 
     * @return a set of successors
     */
    public Set<HornBlock> getSuccessors(final HornBlock blk) {

        Collection<HighCfgVertex<Address, VertexAttributes>> succ =
                this.highCfg.getSuccessors(blk.getVertex());

        //@formatter:off
        return succ.stream()
                   .map(v -> this.hornBlocks.get(v.getLocator()))
                   .filter(b -> b != null)
                   .collect(Collectors.toSet());
        //@formatter:on
    }

    /**
     * Fetch descendants for a block. If successors are blocks that immediately proceed a block,
     * then descendants for a given vertex are all nodes at the outgoing side of an edge, as well as
     * their outgoing vertices, etc. Note that this implementation includes the input block as a
     * descendent
     * 
     * @param blk the block from to compute the descendants
     * 
     * @return the set of descendant blocks
     */
    public Set<HornBlock> getDescendantBlocks(final HornBlock blk) {

        Collection<HighCfgVertex<Address, VertexAttributes>> descendants =
                GraphAlgorithms.getDescendants(this.highCfg,
                        Arrays.asList(blk.getVertex()));

        //@formatter:off
        return descendants.stream()
                          .map(v -> this.hornBlocks.get(v.getLocator()))
                          .filter(b -> b != null)
                          .collect(Collectors.toSet());
        //@formatter:on
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    @Override
    public int hashCode() {
        return function.hashCode();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HornFunction other = (HornFunction) obj;
        if (highCfg == null) {
            if (other.highCfg != null)
                return false;
        } else if (!highCfg.equals(other.highCfg))
            return false;
        if (highFunction == null) {
            if (other.highFunction != null)
                return false;
        } else if (!highFunction.equals(other.highFunction))
            return false;
        return true;
    }

    @Override
    public String toString() {
        if (name != null) {
            return name;
        }
        return "";
    }
}
