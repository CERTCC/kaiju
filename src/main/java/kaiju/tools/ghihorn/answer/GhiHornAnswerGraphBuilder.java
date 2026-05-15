package kaiju.tools.ghihorn.answer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Quantifier;
import com.microsoft.z3.Sort;
import com.google.common.base.Verify;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphEdge;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornFixedPoint;
import kaiju.tools.ghihorn.hornifer.horn.HornClause;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Build the GHiHorn answer graph
 */
public class GhiHornAnswerGraphBuilder {

    // A map of elements indexed by the name
    private Map<String, HornElement> hornElements = new HashMap<>();
    private HornProgram hornProgram;
    private Expr<? extends Sort> z3Answer;
    private GhiHornFixedPoint fixedPoint;
    private GhiHornFixedpointStatus status;

    /**
     * specify the horn program
     * 
     * @param hornProgram
     * @return
     */
    public GhiHornAnswerGraphBuilder forHornProgram(HornProgram hornProgram) {
        this.hornProgram = hornProgram;
        return this;
    }

    /**
     * Set the proof certificate
     * 
     * @param z3Answer
     * @return
     */
    public GhiHornAnswerGraphBuilder forZ3ProofCertificate(final Expr<? extends Sort> z3Answer) {
        this.z3Answer = z3Answer;
        return this;
    }

    /**
     * Set the status
     * 
     * @param status
     * @return
     */
    public GhiHornAnswerGraphBuilder withStatus(final GhiHornFixedpointStatus status) {
        this.status = status;
        return this;
    }

    /**
     * Set the fixed point
     * 
     * @param hfp
     * @return
     */
    public GhiHornAnswerGraphBuilder usingFixedPoint(GhiHornFixedPoint hfp) {
        this.fixedPoint = hfp;
        this.fixedPoint.getRules().forEach(c -> {

            HornElement body = c.getBody();
            String bodyName = (body instanceof HornPredicate) ? ((HornPredicate) body).getFullName()
                    : body.getName();
            hornElements.put(bodyName, body);

            HornElement head = c.getHead();
            String headName = (head instanceof HornPredicate) ? ((HornPredicate) head).getFullName()
                    : head.getName();
            hornElements.put(headName, head);
        });
        return this;
    }

    /**
     * Build the graph
     * 
     * @param status
     * @param hfp
     * @param z3Answer
     */
    public Optional<GhiHornAnswerGraph> build() {

        try {

            Verify.verify(hornProgram != null, "Missing horn program");
            Verify.verify(z3Answer != null, "Missing Z3 proof certificate");
            Verify.verify(status != null, "Missing status");
            Verify.verify(fixedPoint != null, "Missing fixed point");
            Verify.verify(!hornElements.isEmpty(), "Missing horn element information");

            // All prerequisites accounted for

            if (status == GhiHornFixedpointStatus.Satisfiable) {
                return Optional.of(buildSatProof(z3Answer));

            } else if (status == GhiHornFixedpointStatus.Unsatisfiable) {
                return Optional.of(buildUnsatProofGraph());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return Optional.empty();

    }

    /**
     * Get the children for this expression
     * 
     * @param expr
     * @return
     */
    private Expr<?>[] children(Expr<? extends Sort> expr) {
        if (!expr.isApp()) {
            return new Expr[0];
        }
        return expr.getArgs();
    }

    /**
     * Get the fact for the answer expression
     * 
     * @param expr
     * @return the fact
     */
    private Expr<? extends Sort> getFact(final Expr<? extends Sort> expr) {
        Expr<? extends Sort>[] kids = children(expr);
        if (kids != null && kids.length > 0) {
            return kids[kids.length - 1];
        }
        return null;
    }

    /**
     * An unsat proof is a conjunciton of states
     * 
     * @return
     * @throws Exception
     */
    private GhiHornAnswerGraph buildUnsatProofGraph()
            throws Exception {

        Verify.verify(z3Answer.isAnd(), "Assumption about UNSAT answer format proven incorrect");

        Expr<? extends Sort>[] children = children(z3Answer);

        GhiHornAnswerGraph answerGraph =
                new GhiHornAnswerGraph(this.hornProgram, GhiHornFixedpointStatus.Unsatisfiable);

        if (children.length > 0) {

            Map<HornElement, GhiHornAnswerGraphVertex> unsatVertices = new HashMap<>();
            for (int i = 0; i < children.length; i++) {
                GhiHornAnswerGraphVertex vtx =
                        new GhiHornAnswerGraphVertex(makeUnsatVertexAttributes(children[i]));

                unsatVertices.put(vtx.getAttributes().hornElement, vtx);
            }

            for (HornClause clause : this.fixedPoint.getRules()) {

                GhiHornAnswerGraphVertex src = unsatVertices.get(clause.getBody());
                GhiHornAnswerGraphVertex tgt = unsatVertices.get(clause.getHead());

                if (src != null && tgt != null) {
                    if (!answerGraph.containsVertex(src)) {
                        answerGraph.addVertex(src);
                    }
                    if (!answerGraph.containsVertex(tgt)) {
                        answerGraph.addVertex(tgt);
                    }
                    GhiHornAnswerGraphEdge ansEdge = new GhiHornAnswerGraphEdge(src, tgt);
                    if (!answerGraph.containsEdge(ansEdge)) {
                        answerGraph.addEdge(ansEdge);
                    }
                }
            }
        }

        return answerGraph;
    }

    /**
     * 
     * @param expr
     * @param g
     * @param visited
     */
    private void generateSatGraph(final Expr<? extends Sort> expr, GhiHornAnswerGraph g,
            final Map<Expr<? extends Sort>, GhiHornAnswerGraphVertex> exprToVtxMap) {

        if (exprToVtxMap.containsKey(expr)) {
            return;
        }

        final GhiHornAnswerGraphVertex exprVtx =
                new GhiHornAnswerGraphVertex(makeSatVertexAttributes(expr));
        exprToVtxMap.put(expr, exprVtx);

        final Expr<? extends Sort> dst = getFact(expr);
        Expr<? extends Sort>[] kids = children(expr);
        for (int i = 1; i < kids.length - 1; i++) {

            Expr<? extends Sort> kFact = getFact(kids[i]);
            if (!exprToVtxMap.containsKey(kFact)) {

                final GhiHornAnswerGraphVertex vtx =
                        new GhiHornAnswerGraphVertex(makeSatVertexAttributes(kFact));
                g.addVertex(vtx);

                exprToVtxMap.put(kFact, vtx);

                generateSatGraph(kids[i], g, exprToVtxMap);
            }

            GhiHornAnswerGraphVertex srcVtx = exprToVtxMap.getOrDefault(kFact,
                    new GhiHornAnswerGraphVertex(makeSatVertexAttributes(kFact)));

            GhiHornAnswerGraphVertex tgtVtx = exprToVtxMap.getOrDefault(dst,
                    new GhiHornAnswerGraphVertex(makeSatVertexAttributes(dst)));

            g.addEdge(new GhiHornAnswerGraphEdge(srcVtx, tgtVtx));
        }
    }

    /**
     * Build the proof graph if satisfiable
     * 
     * @return
     */
    private GhiHornAnswerGraph buildSatProof(Expr<? extends Sort> answer) throws Exception {

        GhiHornAnswerGraph answerGraph =
                new GhiHornAnswerGraph(this.hornProgram, GhiHornFixedpointStatus.Satisfiable);

        Map<Expr<? extends Sort>, GhiHornAnswerGraphVertex> exprToVtxMap = new HashMap<>();

        answer = children(answer)[0];
        Expr<? extends Sort> fact = getFact(answer);
        final GhiHornAnswerGraphVertex vtx =
                new GhiHornAnswerGraphVertex(makeSatVertexAttributes(fact));

        answerGraph.addVertex(vtx);

        exprToVtxMap.put(fact, vtx);

        generateSatGraph(answer, answerGraph, exprToVtxMap);

        List<GhiHornAnswerGraphVertex> vertices = answerGraph.getVerticesInPreOrder();

        // This is Z3/Spacer cruft that has no bearing on the actual answer
        GhiHornAnswerGraphVertex sink = vertices.get(vertices.size() - 1);
        if (sink.getVertexName().contains("query!")) {
            answerGraph.removeVertex(sink);
        }

        return answerGraph;
    }

    /**
     * 
     * @param expr
     * @return
     */
    private GhiHornUnsatAttributes makeUnsatVertexAttributes(
            final Expr<? extends Sort> expr) {

        Expr<?>[] args = null;
        Set<String> conds = new HashSet<>();

        // It turns out that the unsat answers are quantified expressions conjoined with the
        // conditions that are required
        if (expr.isQuantifier()) {

            Quantifier q = (Quantifier) expr;
            args = q.getBody().getArgs();

            // in the answer the 0th argument is the name of the relation
            String vtxName = args[0].getFuncDecl().getName().toString();
            HornElement vtxElm = hornElements.get(vtxName);

            // If there is an argument, then that will be the reachability clause or the condition
            // that cannot be satisfied

            if (args.length > 1) {

                if (args[1].isConst()) {
                    conds.add(args[1].toString());
                } else {

                    // If this expression is more than just a boolean, then decode the answer based
                    // on variables used

                    // The condition that cannot be evaluated, replace it with meaningful variables
                    Expr<?> cond = args[1];
                    
                    // The arguments of hte expression are the variables in order
                    Expr<?>[] xVars = args[0].getArgs();
                    HornVariable[] hVars = vtxElm.getVariables().toArray(new HornVariable[0]);

                    String condStr = cond.toString();
                    // substitute all the variables so that the names are meaningful
                    for (int i = 0; i < xVars.length; i++) {
                        if (condStr.contains(xVars[i].toString())) {
                            condStr = condStr.replaceAll(xVars[i].toString(),
                                    hVars[i].getVariableName().getName());
                        }
                    }
                    conds.add(condStr);
                }
            }
            return new GhiHornUnsatAttributes(vtxName, vtxElm, conds);
        }

        // Not a quantified expression, so just take the args as they are
        args = expr.getArgs();
        String vtxName = "UNKNOWN";
        if (args.length > 0) {
            vtxName = args[0].getFuncDecl().getName().toString();
        }
        HornElement vtxElm = hornElements.get(vtxName);

        return new GhiHornUnsatAttributes(vtxName, vtxElm, conds);
    }


    /**
     * Create satifiable vertex attributes.
     * 
     * @param expr
     * @return
     */
    private GhiHornSatAttributes makeSatVertexAttributes(
            final Expr<? extends Sort> expr) {

        final String vtxName = expr.getFuncDecl().getName().toString();

        Map<HornVariable, String> varVals = new HashMap<>();
        if (hornElements.containsKey(vtxName) && !vtxName.isEmpty()) {

            HornElement hornElm = hornElements.get(vtxName);
            List<HornVariable> elmVars = new ArrayList<>(hornElm.getVariables());
            Expr<?>[] vals = expr.getArgs();

            for (int i = 0; i < elmVars.size(); i++) {
                if (vals[i].isArray() || vals[i].isSelect()) {
                    varVals.put(elmVars.get(i), "N/A");
                } else {
                    varVals.put(elmVars.get(i), vals[i].toString());
                }
            }
        }

        final HornElement elm = hornElements.get(vtxName);
        return new GhiHornSatAttributes(vtxName, elm, varVals);
    }
}
