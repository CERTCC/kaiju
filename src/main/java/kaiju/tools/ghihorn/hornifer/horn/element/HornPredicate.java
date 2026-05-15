package kaiju.tools.ghihorn.hornifer.horn.element;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.Sort;
import com.google.common.base.Verify;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableExpression;
import kaiju.tools.ghihorn.z3.GhiHornContext;

/**
 * A predicate, which is an instance
 */
public class HornPredicate implements HornElement {

    protected final String name;
    protected final String id;

    // As with other horn containers, variables are to be sorted by name
    protected final SortedSet<HornVariable> variables = new TreeSet<>(
            Comparator.comparing(HornVariable::getName, Comparator.nullsFirst(String::compareTo)));

    private final ProgramLocation locator;
    protected boolean isPrecondition, isPostcondition, isImported, isExternal, isEntry;
    protected HornBlock blk;

    /**
     * Create a new predicate
     * 
     * @param name The name of the predicate
     * @param id The ID for this predicate
     * @param loc The locator for this predicate
     * @param vars The variables for this predicate (if any)
     */

    public HornPredicate(final String name, final String id, ProgramLocation loc,
            HornVariable... vars) {

        this.name = name;
        this.locator = loc;
        this.id = id;

        if (vars != null && vars.length > 0) {
            this.variables.addAll(Arrays.asList(vars));
        }

        // Optional properties
        this.blk = null;
        this.isImported = false;
        this.isExternal = false;
        this.isPostcondition = false;
        this.isPrecondition = false;
    }

    /**
     * Copy constructor
     * 
     * @param other the other predicate
     */
    public HornPredicate(HornPredicate other) {
        this.name = other.name;
        this.locator = other.locator;
        this.id = other.id;

        other.variables.forEach(v -> this.variables.add(new HornVariable(v)));

        // Optional properties
        this.blk = other.blk;
        this.isImported = other.isImported;
        this.isExternal = other.isExternal;
        this.isPostcondition = other.isPostcondition;
        this.isPrecondition = other.isPrecondition;
    }

    /**
     * Create a predicate with a name and locator, but no other data, such as a xref
     * 
     * @param n
     */
    public HornPredicate(final String n, ProgramLocation loc, HornVariable... vars) {
        this.name = n;
        this.locator = loc;

        this.id = NO_ID;
        this.blk = null;
        this.isImported = false;
        this.isExternal = false;
        this.isPostcondition = false;
        this.isPrecondition = false;

        if (vars != null && vars.length > 0) {
            this.variables.addAll(Arrays.asList(vars));
        }
    }

    /**
     * @return the locator
     */
    @Override
    public ProgramLocation getLocator() {
        return locator;
    }

    /**
     * Compute the state for this predicate based on the basic block
     * 
     * @return the state of the block as a map from
     */
    public Map<Expr<? extends Sort>, Expr<? extends Sort>> computeState(GhiHornContext ctx) {

        if (blk != null) {

            final Map<Expr<? extends Sort>, Expr<? extends Sort>> initialState =
                    blk.instantiateState(ctx);
            final Map<Expr<? extends Sort>, Expr<? extends Sort>> finalState =
                    new HashMap<>(initialState.size());

            // The expressions must be made into specific instances wit the ID
            // string

            for (Map.Entry<Expr<? extends Sort>, Expr<? extends Sort>> stateEntry : initialState
                    .entrySet()) {

                Expr<? extends Sort> inExpr = stateEntry.getKey();
                Expr<? extends Sort> outExpr = stateEntry.getValue();

                for (HornVariable variable : this.variables) {
                    final Expr<? extends Sort> varExpr = variable.instantiate(ctx);

                    inExpr = inExpr.substitute(varExpr, variable.instantiate(ctx));
                    outExpr = outExpr.substitute(varExpr, variable.instantiate(ctx));
                }

                finalState.put(inExpr, outExpr);
            }
            return finalState;
        }
        // Careful not to return null
        return new HashMap<>();
    }

    /**
     * @return the full name
     */
    public String getFullName() {
        StringBuilder sb = new StringBuilder(name);
        if (!this.id.equals(NO_ID)) {
            sb.append("_").append(id);
        }
        return sb.toString();

    }

    /**
     * @return the name
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * @return the id
     */
    @Override
    public String getInstanceId() {
        return this.id;
    }

    /**
     * Fetch the variables sorted by name
     */
    public SortedSet<HornVariable> getVariables() {
        return this.variables;
    }

    public void addVariable(final HornVariable newVar) {
        this.variables.add(newVar);
    }

    public void addVariables(final Set<HornVariable> newVarSet) {
        this.variables.addAll(newVarSet);
    }

    /**
     * Declare the relation/function for this prediate
     * 
     * @param ctx
     * @param vars
     * @return
     */
    @Override
    public FuncDecl<BoolSort> declare(final GhiHornContext ctx) {
        final String fullName = getFullName();

        List<Sort> sorts =
                this.variables.stream().map(v -> v.getDataType().mkSort(ctx)).filter(s -> s != null)
                        .collect(Collectors.toList());

        if (sorts != null && !sorts.isEmpty()) {
            return ctx.mkRelation(fullName, sorts.toArray(new Sort[0]));
        }

        return ctx.mkRelation(fullName);
    }

    /**
     * Instantiate this predicate for a list of variables
     * 
     * @param ctx a valid context
     * @param vars
     * @return
     */
    @Override
    public BoolExpr instantiate(final GhiHornContext ctx, HornVariableExpression... vars) {

        Verify.verify(this.variables.size() == vars.length, "Mismatched variables in: " + name);

        List<Expr<? extends Sort>> varExprs = new ArrayList<>(vars.length);
        for (int i = 0; i < vars.length; i++) {
            Expr<? extends Sort> valI = vars[i].instantiate(ctx);
            varExprs.add(i, valI);
        }
        return (BoolExpr) declare(ctx).apply(varExprs.toArray(new Expr[0]));
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(this.name);
        if (!this.id.equals(NO_ID)) {
            sb.append("_").append(this.id);
        }
        sb.append("(");
        this.variables.forEach(v -> sb.append(v).append(","));
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.delete(sb.length() - 1, sb.length());
        }
        sb.append(")");
        return sb.toString();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((blk == null) ? 0 : blk.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + (isEntry ? 1231 : 1237);
        result = prime * result + (isExternal ? 1231 : 1237);
        result = prime * result + (isImported ? 1231 : 1237);
        result = prime * result + (isPostcondition ? 1231 : 1237);
        result = prime * result + (isPrecondition ? 1231 : 1237);
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((variables == null) ? 0 : variables.hashCode());
        return result;
    }

    /**
     * A HornBlock backs this predicate
     * 
     * @param b
     */
    public void setHornBlock(HornBlock b) {
        this.blk = b;

        setImported(blk.isImported());
        setExternal(blk.isExternal());
    }

    /**
     * @return the blk
     */
    public Optional<HornBlock> getHornBlock() {
        return (blk != null) ? Optional.of(blk) : Optional.empty();
    }

    public boolean hasHornBlock() {
        return (blk != null);
    }

    public void makePrecondition() {
        this.isPrecondition = true;
    }

    public void makePostcondition() {
        this.isPrecondition = true;
    }

    /**
     * @return the isPrecondition
     */
    public boolean isPrecondition() {
        return isPrecondition;
    }

    /**
     * @return the isPostcondition
     */
    public boolean isPostcondition() {
        return isPostcondition;
    }

    /**
     * @param isEntry the isEntry to set
     */
    public void makeEntry() {
        this.isEntry = true;
    }

    public void setImported(boolean isImp) {
        this.isImported = isImp;
    }

    /**
     * A predicate is external if it is not backed by an implementation (e.g. an external block)
     * 
     * @param isExt
     */
    public void setExternal(boolean isExt) {
        this.isExternal = isExt;
    }

    /**
     * @return the isEntry
     */
    public boolean isEntry() {
        return isEntry;
    }

    public boolean isImported() {
        return this.isImported;
    }

    /**
     * A predicate is external if it is not backed by an implementation (e.g. an external block)
     */
    public boolean isExternal() {
        return this.isExternal;
    }

    public static String addressToId(Address startAddress) {
        try {
            return Long.toHexString(startAddress.getUnsignedOffset());
        } catch (Exception x) {
            return NO_ID;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */

    @Override
    public boolean equals(Object obj) {


        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final HornPredicate other = (HornPredicate) obj;

        // With all the object parts being equal, check the locator
        if (locator != null && other.locator != null) {
            if (locator.compareTo(other.locator) != 0) {
                return false;
            }
        } else if (id == null) {
            if (other.id != null) {
                return false;
            }
        } else if (!id.equals(other.id)) {
            return false;
        }
        if (isEntry != other.isEntry) {
            return false;
        }
        if (isExternal != other.isExternal) {
            return false;
        }
        if (isImported != other.isImported) {
            return false;
        }
        if (isPostcondition != other.isPostcondition) {
            return false;
        }
        if (isPrecondition != other.isPrecondition) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }

        return true;
    }
}
