package kaiju.ghihorn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import com.google.common.base.VerifyException;
import com.microsoft.z3.ArraySort;
import com.microsoft.z3.BitVecSort;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.BoolSort;
import com.microsoft.z3.Expr;
import com.microsoft.z3.IntSort;
import com.microsoft.z3.Sort;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import generic.stl.Pair;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import kaiju.common.di.GhidraDI;
import kaiju.tools.ghihorn.answer.GhiHornSatAttributes;
import kaiju.tools.ghihorn.answer.GhiHornUnsatAttributes;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettingBuilder;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.format.GhiHornOutputFormatter;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.api.ApiEntry;
import kaiju.tools.ghihorn.cmd.GhiHornCommand;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.block.HornBlock;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.hornifer.horn.HornClause;
import kaiju.tools.ghihorn.hornifer.horn.HornFunctionInstance;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.HornRuleExpr;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.expression.BoolNotExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.BoolOrExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.EqExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.HornExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.PcodeExpression;
import kaiju.tools.ghihorn.hornifer.horn.expression.SltExpression;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornConstant;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable.Scope;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariableName;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerArgument;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiFunction;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiSignature;
import kaiju.tools.ghihorn.z3.GhiHornArrayType;
import kaiju.tools.ghihorn.z3.GhiHornBitVectorType;
import kaiju.tools.ghihorn.z3.GhiHornBooleanType;
import kaiju.tools.ghihorn.z3.GhiHornContext;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;
import kaiju.tools.ghihorn.z3.GhiHornIntegerType;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GhiHornTest extends AbstractGhidraHeadedIntegrationTest {
    private GhiHornContext ctx;
    private GhiHornTestEnv testEnv;

    public GhiHornTest() {}

    @BeforeEach
    public void beforeEach() throws Exception {
        ctx = new GhiHornContext();
    }

    @AfterEach
    public void afterEach() throws Exception {
        ctx.close();
    }

    @AfterAll
    public void afterAll() {
        testEnv.dispose();
        Msg.info(this, "*****************************************\nCompleted.");
    }

    @BeforeAll
    public void beforeAll() throws IOException {
        testEnv = new GhiHornTestEnv(new TestEnv());
        try {
            testEnv.configure();
        } catch (Exception e) {
            e.printStackTrace();
            Msg.error(this, "Failed to configure environment");
        }
        setErrorGUIEnabled(false);
    }

    @Nested
    @DisplayName("GhiHorn Z3 tests")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class Z3Tests {

        private AddressFactory addrFactory;
        private Varnode regEAX;
        private Varnode mem1;
        private Varnode const42;

        @BeforeAll
        public void setUp() throws Exception {

            Language lang = getSLEIGH_X86_LANGUAGE();
            Program program = createDefaultProgram("Test", ProgramBuilder._X86, this);
            addrFactory = program.getAddressFactory();
            Register reg = lang.getRegister("EAX");

            regEAX = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
            mem1 = new Varnode(addr(100), 1);
            const42 = new Varnode(addrFactory.getConstantAddress(42), 4);
        }

        private Address addr(long offset) {
            return addrFactory.getDefaultAddressSpace().getAddress(offset);
        }

        /**
         * 
         * @throws Exception
         */
        public void testMemoryStore() throws Exception {

            TestEnv env = new TestEnv();
            HighFunction hf = testEnv
                    .buildTestFunction("Test",
                            "55 8b ec 51 a1 a0 3f 00 10 8b 0d a0 3f 00 10 89 0c 85 00 30 00 10 8b 15"
                                    + "a0 3f 00 10 89 55 fc a1 a0 3f 00 10 83 c0 01 a3 a0 3f 00 10 8b 45 fc 8b"
                                    + "e5 5d c2 1c 00",
                            ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.STORE) {

                    BoolExpr x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.toString()
                            .equals("(= Memory (store Memory piVar25@FUN_00001000 DAT_10003fa0))"));
                }
            }

            env.dispose();

        }

        @Test
        public void test2sCompOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 d1 00 00 00 31 c9 89 45 fc 2b 4d fc 89 c8 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_2COMP) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.getArgs()[1].isBVNOT());

                }
            }
        }

        @Test
        public void testAddOp() {

            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_ADD,
                    new Varnode[] {regEAX, const42}, mem1);

            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVAdd());

        }

        @Test
        public void testLessEqualOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_LESSEQUAL,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVULE());

        }

        @Test
        public void testSlesslOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_SLESS,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVSLT());
        }

        @Test
        public void testSlessEqualOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_SLESSEQUAL,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVSLE());
        }

        @Test
        public void testSextOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_SEXT,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVSignExtension());
        }

        @Test
        public void testSubOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_SUB,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVSub());
        }

        @Test
        public void testDivOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_DIV,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVUDiv());
        }

        @Test
        public void testBvOrOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_OR,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVOR());
        }

        @Test
        public void testOrOp() {
            // Test that a logical OR results in a proper disjunction
            List<HornExpression> orList = new ArrayList<>();
            orList.add(new EqExpression(new HornConstant(0), new HornConstant(0)));
            orList.add(new EqExpression(new HornConstant(1), new HornConstant(1)));
            orList.add(new EqExpression(new HornConstant(2), new HornConstant(2)));
            orList.add(new EqExpression(new HornConstant(3), new HornConstant(3)));
            orList.add(new EqExpression(new HornConstant(4), new HornConstant(4)));

            Expr<? extends Sort> orX = new BoolOrExpression(orList).instantiate(ctx);

            assertTrue(orX.isOr());
            assertTrue(orX.getArgs().length == 5);
        }

        @Test
        public void testXorOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_XOR,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVXOR());
        }

        @Test
        public void testNegateOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_NEGATE,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVNOT());
        }

        @Test
        public void testNeOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_NOTEQUAL,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);

            Expr<?>[] args = x.getArgs();
            assertTrue(args[1].isNot());

            assertTrue(args[1].getArgs()[0].isEq());
        }

        @Test
        public void testSRemOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_SREM,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVSRem());
        }

        @Test
        public void testURemOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_REM,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVURem());
        }

        @Test
        public void testLoadOp() {
            PcodeOp pcode =
                    new PcodeOp(addr(1000), 0, PcodeOp.LOAD, new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isSelect());
            // using the memory expression
            assertTrue(x.getArgs()[1].getArgs()[0].equals(ctx.getMemoryExpr()));
        }

        @Test
        public void testStoreOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.STORE,
                    new Varnode[] {regEAX, const42, regEAX}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isEq());
            var xArgs = x.getArgs()[1].getArgs();

            // using the memory expression
            assertTrue(xArgs[0].equals(ctx.getMemoryExpr()));
            assertTrue(xArgs[1].isStore());
        }

        @Test
        public void testPtrAddOp() {

            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.PTRADD,
                    new Varnode[] {regEAX, const42, const42},
                    mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);

            // Currently, PTRADD is a simple addition
            assertTrue(x.getArgs()[1].isBVMul());
        }

        @Test
        public void testPtrSubOp() {

            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.PTRSUB,
                    new Varnode[] {regEAX, const42, const42},
                    mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);

            // Currently, PTRSUB is a simple subtraction
            assertTrue(x.getArgs()[1].isBVAdd());
        }

        @Test
        public void testEqOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_EQUAL,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);

            Expr<?>[] args = x.getArgs();
            assertTrue(args[1].isEq());

            // Disallow mized types
            HornExpression boolX = new HornVariable(new HornVariableName("rhs"),
                    new GhiHornBooleanType(), Scope.Local);
            HornExpression bvX = new HornVariable(new HornVariableName("rhs"),
                    new GhiHornBitVectorType(), Scope.Local);
            try {
                new EqExpression(bvX, boolX).instantiate(ctx);
                new EqExpression(boolX, bvX).instantiate(ctx);
                fail();
            } catch (VerifyException ve) {
            }
        }

        @Test
        public void testShlOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_LEFT,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);

            Expr<?>[] args = x.getArgs();
            assertTrue(args[1].isBVShiftLeft());
        }

        @Test
        public void testShrOp() {
            PcodeOp pcode = new PcodeOp(addr(1000), 0, PcodeOp.INT_RIGHT,
                    new Varnode[] {regEAX, const42}, mem1);
            Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
            assertTrue(x.getArgs()[1].isBVShiftRightLogical());
        }

        @Test
        public void testMultOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 a1 01 00 00 89 45 fc 8b 45 fc 0f af 45 fc 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);
            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_MULT) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.getArgs()[1].isBVMul());

                }
            }
        }

        @Test
        public void testCastOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 21 02 00 00 89 45 fc 8b 45 fc 03 45 fc 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);
            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.CAST) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.isEq());

                }
            }
        }

        @Test
        public void testSrightOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 61 01 00 00 89 45 fc 8b 45 fc c1 f8 02 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);
            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_SRIGHT) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.getArgs()[1].isBVShiftRightArithmetic());

                }
            }
        }

        @Test
        public void testSdivOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 e1 01 00 00 89 45 fc 8b 45 fc 99 f7 7d fc 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);
            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_SDIV) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.getArgs()[1].isBVSDiv());
                }
            }
        }

        @Test
        public void testUseVar() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 81 00 00 00 89 45 fc 8b 45 fc 83 e0 01 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_AND) {
                    PcodeExpression px = new PcodeExpression(pcode);
                    List<HornVariable> u = px.getUseVariables();

                    assertTrue(u.size() == 1);
                    assertTrue(u.get(0).getName().equals("uVar1@FUN_00001000!Test"));
                }
            }
        }

        @Test
        public void testVarName() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 81 00 00 00 89 45 fc 8b 45 fc 83 e0 01 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_AND) {
                    PcodeExpression px = new PcodeExpression(pcode);
                    List<HornVariable> u = px.getUseVariables();
                    HornVariable v1 = u.get(0);
                    assertEquals(v1.getName(), "uVar1@FUN_00001000!Test");
                }
            }
        }

        @Test
        public void testVarNameComponents() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 81 00 00 00 89 45 fc 8b 45 fc 83 e0 01 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_AND) {
                    PcodeExpression px = new PcodeExpression(pcode);
                    List<HornVariable> u = px.getUseVariables();
                    HornVariable v1 = u.get(0);

                    HornVariableName hvn = v1.getVariableName();
                    assertTrue(hvn.getName().equals("uVar1"));
                    assertTrue(hvn.getFuncId().equals("FUN_00001000"));
                    assertTrue(hvn.getProgramId().equals("Test"));
                }
            }
        }

        @Test
        public void testConst() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 81 00 00 00 89 45 fc 8b 45 fc 83 e0 01 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_AND) {
                    PcodeExpression px = new PcodeExpression(pcode);
                    List<HornVariable> u = px.getInVariables();
                    HornVariable v2 = u.get(1);

                    assertTrue(v2 instanceof HornConstant);
                    HornConstant c = (HornConstant) v2;
                    assertTrue(c.getValue() == 1);
                }
            }
        }

        @Test
        public void testDefVar() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 81 00 00 00 89 45 fc 8b 45 fc 83 e0 01 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_AND) {
                    PcodeExpression px = new PcodeExpression(pcode);
                    List<HornVariable> d = px.getDefVariables();

                    assertTrue(d.size() == 1, "Incorrect def var count");
                    assertTrue(d.get(0).getName().equals("uVar112@FUN_00001000!Test"),
                            "Incorrect def var name");
                }
            }
        }

        @Test
        public void testAndOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 81 00 00 00 89 45 fc 8b 45 fc 83 e0 01 48 83 c4 10 5d c3",
                    ProgramBuilder._X86);

            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_AND) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.getArgs()[1].isBVAND());
                }
            }
        }

        @Test
        public void testLtOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 e1 02 00 00 89 45 f8 83 7d f8 02 0f 8f 0c 00 00 00 c7 45 fc 01 00 00 00 e9 07 00 00 00 c7 45 fc 00 00 00 00 8b 45 fc 48 83 c4 10 5d c3",
                    ProgramBuilder._X64);
            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {
                if (pcode.getOpcode() == PcodeOp.INT_SLESS) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.getArgs()[1].isBVSLT());
                }
            }
        }

        @Test
        public void testZextOp() {
            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 48 83 ec 10 b0 00 e8 41 00 00 00 89 45 fc 8b 45 fc 23 45 fc 48 83 c4 10 5d c3",
                    ProgramBuilder._X64);
            Iterable<PcodeOpAST> itbl = () -> hf.getPcodeOps();

            for (final PcodeOp pcode : itbl) {

                if (pcode.getOpcode() == PcodeOp.INT_ZEXT) {
                    Expr<? extends Sort> x = new PcodeExpression(pcode).instantiate(ctx);
                    assertTrue(x.getArgs()[1].isBVZeroExtension());
                }
            }
        }

        @Test
        public void testApiNameEntry() {

            ApiEntry entry = ApiEntry.create("kernel32.dll", "_CreateFileA@24");
            assertTrue(entry.formatApiName().equals("KERNEL32.DLL::CREATEFILEA"));
        }
    }

    @Nested
    @DisplayName("Hornification Tests")
    class HornifierTest {

        @Test
        public void testMakeIntVariable() {
            HornVariable i = new HornVariable(new HornVariableName("i"), new GhiHornIntegerType(),
                    Scope.Local);
            Expr<? extends Sort> c = i.getDataType().mkConst(ctx, "i");
            assertTrue(c.getSort() instanceof IntSort);
        }

        @Test

        public void testMakeBoolVariable() {
            HornVariable b = new HornVariable(new HornVariableName("b"), new GhiHornBooleanType(),
                    Scope.Local);
            Expr<? extends Sort> c = b.getDataType().mkConst(ctx, "b");
            assertTrue(c.getSort() instanceof BoolSort);
        }

        @Test
        public void testMakeArrayVariable() {

            GhiHornArrayType at =
                    new GhiHornArrayType(new GhiHornIntegerType(), new GhiHornBitVectorType());
            HornVariable x = new HornVariable(new HornVariableName("a"), at, Scope.Local);
            Expr<? extends Sort> c = x.getDataType().mkConst(ctx, "a");

            assertTrue(c.getSort() instanceof ArraySort);
            assertTrue(at.getIndexDataType().mkConst(ctx, "v").getSort() instanceof IntSort);
            assertTrue(at.getValueDataType().mkConst(ctx, "bv").getSort() instanceof BitVecSort);
        }

        @Test
        // This test is broken on Ghidra 10.4 for unknown reasons. Jeff is
        // looking into it.
        #if GHIDRA_10_4 == "true" @Disabled #endif
        public void testHornBlockVariables() {

            // ************************************************************************
            //
            // The bytestring results in this function:
            // blk1
            // 00001000: PUSH EBP (GhiHornTest)
            // 00001001: DEC EAX (GhiHornTest)
            // 00001002: MOV EBP,ESP (GhiHornTest)
            // 00001004: MOV dword ptr [EBP + -0x4],0x0 (GhiHornTest)
            // 0000100b: CMP dword ptr [0x0000006e],0x64 (GhiHornTest)
            // 00001012: JLE 0x00001024 (GhiHornTest)

            // blk2
            // 00001018: MOV dword ptr [EBP + -0x8],0xa (GhiHornTest)
            // 0000101f: JMP 0x0000102b (GhiHornTest)

            // blk3
            // 00001024: MOV dword ptr [EBP + -0x8],0x14 (GhiHornTest)

            // blk4
            // 0000102b: MOV EAX,dword ptr [EBP + -0x8] (GhiHornTest)
            // 0000102e: POP EBP (GhiHornTest)
            // 0000102f: RET (GhiHornTest)

            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 c7 45 fc 00 00 00 00 83 3d 6e 00 00 00 64 0f 8e 0c"
                            + "00 00 00 c7 45 f8 0a 00 00 00 e9 07 00 00 00 c7 45 f8 14 00 00 00 8b 45 f8 5d c3",
                    ProgramBuilder._X86);

            try {

                Program program = hf.getFunction().getProgram();
                Address start = hf.getFunction().getBody().getMinAddress();
                Address end = hf.getFunction().getBody().getMaxAddress();
                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);

                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram =
                        hornifier.hornify(program, TaskMonitor.DUMMY);

                var blocks = hornProgram.getHornFunctions().iterator().next().getBlocks();
                for (HornBlock blk : blocks) {

                    if (blk.getStartAddress().toString().equals("0000102b")) {
                        int defCount = 0;
                        for (var d : blk.getDefVariables()) {
                            if (d.getName().equals("DAT_0000006e!Test"))
                                defCount++;
                            else if (d.getName().equals("uVar90@FUN_00001000!Test"))
                                defCount++;
                            else if (d.getName().equals("local_c@FUN_00001000!Test"))
                                defCount++;
                        }
                        assertTrue(defCount == 3, "Block 0000102b has incorrect def var count");

                        int useCount = 0;
                        for (var u : blk.getUseVariables()) {
                            if (u.getName().equals("DAT_0000006e!Test"))
                                useCount++;
                            else if (u.getName().equals("local_c@FUN_00001000!Test"))
                                useCount++;
                        }
                        assertTrue(useCount == 2, "Block 0000102b has incorrect use var count");

                        // * (stack, 0xfffffffffffffff4, 4) MULTIEQUAL (stack, 0xfffffffffffffff4,
                        // 4) ,
                        // (stack, 0xfffffffffffffff4, 4)
                        // * (register, 0x0, 4) COPY (stack, 0xfffffffffffffff4, 4)
                        // * (ram, 0x6e, 4) COPY (ram, 0x6e, 4)
                        // * --- RETURN (const, 0x0, 4) , (register, 0x0, 4)
                        assertTrue(blk.getExpressions().size() == 4);
                    }

                    else if (blk.getStartAddress().toString().equals("00001018")) {

                        // ---------- Def:
                        // * local_c@FUN_00001000
                        HornVariable d = blk.getDefVariables().iterator().next();
                        assertTrue(d.getName().equals("local_c@FUN_00001000!Test"),
                                "Block 0000102b has incorrect def count");
                        assertTrue(blk.getUseVariables().isEmpty(),
                                "Block 00001018 has incorrect use count");

                        // ---------- Exprs:
                        // * (stack, 0xfffffffffffffff4, 4) COPY (const, 0xa, 4)
                        // * --- BRANCH (ram, 0x102b, 1)
                        // "
                        assertTrue(blk.getExpressions().size() == 2,
                                "Block 00001018 has incorrect P-Code");
                    }

                    else if (blk.getStartAddress().toString().equals("00001024")) {

                        // "==========
                        // 00001024
                        // ---------- Def:
                        // * local_c@FUN_00001000
                        HornVariable d = blk.getDefVariables().iterator().next();
                        assertTrue(d.getName().equals("local_c@FUN_00001000!Test"),
                                "Block 00001024 has incorrect def variable");
                        assertTrue(blk.getUseVariables().isEmpty(),
                                "Block 0000102b has incorrect use count");
                        // ---------- Exprs:
                        // * (stack, 0xfffffffffffffff4, 4) COPY (const, 0x14, 4)
                        // "
                        assertTrue(blk.getExpressions().size() == 1);
                    }

                    else if (blk.getStartAddress().toString().equals("00001000")) {

                        // "==========
                        // 00001000
                        // ---------- Def:
                        // * bVar70@FUN_00001000
                        HornVariable d = blk.getDefVariables().iterator().next();
                        assertTrue(d.getName().equals("bVar70@FUN_00001000!Test"));

                        // ---------- Use:
                        // * DAT_0000006e
                        HornVariable u = blk.getUseVariables().iterator().next();

                        assertTrue(u.getName().equals("DAT_0000006e!Test"),
                                "Block 00001000 has incorrect def count");

                        // ---------- Exprs:
                        // * (unique, 0x8700, 1) INT_SLESS (ram, 0x6e, 4) , (const, 0x65, 4)
                        // * --- CBRANCH (ram, 0x1024, 1) , (unique, 0x8700, 1)
                        // "
                        assertTrue(blk.getExpressions().size() == 2);
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testHornify() {

            // ************************************************************************
            //
            // The bytestring results in this function:
            //
            // 00001000: PUSH EBP (GhiHornTest)
            // 00001001: DEC EAX (GhiHornTest)
            // 00001002: MOV EBP,ESP (GhiHornTest)
            // 00001004: MOV dword ptr [EBP + -0x4],0x0 (GhiHornTest)
            // 0000100b: CMP dword ptr [0x0000006e],0x64 (GhiHornTest)
            // 00001012: JLE 0x00001024 (GhiHornTest)
            // 00001018: MOV dword ptr [EBP + -0x8],0xa (GhiHornTest)
            // 0000101f: JMP 0x0000102b (GhiHornTest)
            // 00001024: MOV dword ptr [EBP + -0x8],0x14 (GhiHornTest)
            // 0000102b: MOV EAX,dword ptr [EBP + -0x8] (GhiHornTest)
            // 0000102e: POP EBP (GhiHornTest)
            // 0000102f: RET (GhiHornTest)

            //@formatter:off
            // 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000) && DAT_0000006e (S)< const=65 -> 00001024_1000(DAT_0000006e,Memory,v3@FUN_00001000)
            // 0000102b_1000(DAT_0000006e,Memory,iVar90@FUN_00001000,v3@FUN_00001000) -> FUN_00001000_post_1000(DAT_0000006e,Memory,iVar90@FUN_00001000)
            // FUN_00001000_pre_1000(DAT_0000006e,Memory) -> 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000)
            // 00001018_1000(DAT_0000006e,Memory,v3@FUN_00001000) -> 0000102b_1000(DAT_0000006e,Memory,iVar90@FUN_00001000,v3@FUN_00001000)
            // 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000) && !DAT_0000006e (S)<  const=65 -> 00001018_1000(DAT_0000006e,Memory,v3@FUN_00001000)
            // 00001024_1000(DAT_0000006e,Memory,v3@FUN_00001000) -> 0000102b_1000(DAT_0000006e,Memory,iVar90@FUN_00001000,v3@FUN_00001000)
            //@formatter:on
            //
            // ************************************************************************

            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 c7 45 fc 00 00 00 00 83 3d 6e 00 00 00 64 0f 8e 0c"
                            + "00 00 00 c7 45 f8 0a 00 00 00 e9 07 00 00 00 c7 45 f8 14 00 00 00 8b 45 f8 5d c3",
                    ProgramBuilder._X86);

            try {

                Program program = hf.getFunction().getProgram();
                Address start = hf.getFunction().getBody().getMinAddress();
                Address end = hf.getFunction().getBody().getMaxAddress();
                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram =
                        hornifier.hornify(program, TaskMonitor.DUMMY);

                int correctClauseCount = 0;
                boolean foundPre = false, foundPost = false;
                for (HornClause clause : hornProgram.getClauses()) {
                    String clauseName = clause.getName();
                    List<HornExpression> constraints = clause.getConstraints();

                    // 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000) && DAT_0000006e (S)<
                    // const=65 -> 00001024_1000(DAT_0000006e,Memory,v3@FUN_00001000)
                    if (clauseName.equals("00001000-00001024")) {
                        ++correctClauseCount;
                        assertTrue(constraints.size() == 1);
                        HornExpression x = constraints.get(0);
                        assertTrue(x instanceof SltExpression,
                                "Constraint wrong type: " + x.getClass().toString());
                    }
                    // 0000102b_1000(DAT_0000006e,Memory,iVar90@FUN_00001000,v3@FUN_00001000) ->
                    // FUN_00001000_post_1000(DAT_0000006e,Memory,iVar90@FUN_00001000)
                    if (clauseName.equals("0000102b-FUN_00001000_post_1000")) {
                        foundPost = true;
                        ++correctClauseCount;
                    }
                    // FUN_00001000_pre_1000(DAT_0000006e,Memory) ->
                    // 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000)
                    if (clauseName.equals("FUN_00001000_pre_1000-00001000")) {
                        foundPre = true;
                        ++correctClauseCount;
                    }
                    // 00001018_1000(DAT_0000006e,Memory,v3@FUN_00001000) ->
                    // 0000102b_1000(DAT_0000006e,Memory,iVar90@FUN_00001000,v3@FUN_00001000)
                    if (clauseName.equals("00001018-0000102b")) {
                        ++correctClauseCount;
                    }
                    // 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000) && !DAT_0000006e (S)<
                    // const=65 -> 00001018_1000(DAT_0000006e,Memory,v3@FUN_00001000)
                    if (clauseName.equals("00001000-00001018")) {
                        ++correctClauseCount;
                        assertTrue(constraints.size() == 1);
                        HornExpression x = constraints.get(0);
                        assertTrue(x instanceof BoolNotExpression,
                                "Constraint wrong type: " + x.getClass().toString());
                    }
                    // 00001024_1000(DAT_0000006e,Memory,v3@FUN_00001000) ->
                    // 0000102b_1000(DAT_0000006e,Memory,iVar90@FUN_00001000,v3@FUN_00001000)
                    if (clauseName.equals("00001024-0000102b")) {
                        ++correctClauseCount;
                    }
                }

                // Check correct structure
                assertTrue(foundPost);
                assertTrue(foundPre);
                assertTrue(correctClauseCount == 6,
                        "Incorrect clauses found (" + correctClauseCount + ")");

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        /**
         * Test that conditions are properly hornified on choices
         */
        public void testHornifyCondition() {

            // ************************************************************************
            //
            // The bytestring results in this function:
            //
            // 00001000: PUSH EBP (GhiHornTest)
            // 00001001: DEC EAX (GhiHornTest)
            // 00001002: MOV EBP,ESP (GhiHornTest)
            // 00001004: MOV dword ptr [EBP + -0x4],0x0 (GhiHornTest)
            // 0000100b: CMP dword ptr [0x0000006e],0x64 (GhiHornTest)
            // 00001012: JLE 0x00001024 (GhiHornTest)
            // 00001018: MOV dword ptr [EBP + -0x8],0xa (GhiHornTest)
            // 0000101f: JMP 0x0000102b (GhiHornTest)
            // 00001024: MOV dword ptr [EBP + -0x8],0x14 (GhiHornTest)
            // 0000102b: MOV EAX,dword ptr [EBP + -0x8] (GhiHornTest)
            // 0000102e: POP EBP (GhiHornTest)
            // 0000102f: RET (GhiHornTest)

            //@formatter:off
            // 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000) && DAT_0000006e (S)< const=65 -> 00001024_1000(DAT_0000006e,Memory,v3@FUN_00001000)
            // 00001000_1000(DAT_0000006e,Memory,bVar70@FUN_00001000) && !DAT_0000006e (S)< const=65 -> 00001018_1000(DAT_0000006e,Memory,v3@FUN_00001000)
            //@formatter:on
            //
            // ************************************************************************

            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 c7 45 fc 00 00 00 00 83 3d 6e 00 00 00 64 0f 8e 0c"
                            + "00 00 00 c7 45 f8 0a 00 00 00 e9 07 00 00 00 c7 45 f8 14 00 00 00 8b 45 f8 5d c3",
                    ProgramBuilder._X86);

            try {

                Program program = hf.getFunction().getProgram();
                Address start = hf.getFunction().getBody().getMinAddress();
                Address end = hf.getFunction().getBody().getMaxAddress();
                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornifier hornifier = toolPair.second;
                final HornProgram hornProgram =
                        hornifier.hornify(program, TaskMonitor.DUMMY);

                List<HornClause> choice = new ArrayList<>();
                for (HornClause clause : hornProgram.getClauses()) {
                    if (clause.getBody().getName().equals("00001000_1000")) {
                        choice.add(clause);
                    }
                }

                // Basically the conditions should have the same body and different heads
                // controlled by negated condition
                HornExpression c0x = choice.get(0).getConstraints().get(0);
                HornExpression c1x = choice.get(1).getConstraints().get(0);
                if (c0x.toString().equals("DAT_0000006e (S)< const=65")) {
                    assertTrue(c1x.toString().equals("!DAT_0000006e (S)< const=65"));
                } else if (c0x.toString().equals("!DAT_0000006e (S)< const=65")) {
                    assertTrue(c1x.toString().equals("DAT_0000006e (S)< const=65"));
                }
                if (c1x.toString().equals("DAT_0000006e (S)< const=65")) {
                    assertTrue(c0x.toString().equals("!DAT_0000006e (S)< const=65"));
                } else if (c1x.toString().equals("!DAT_0000006e (S)< const=65")) {
                    assertTrue(c0x.toString().equals("DAT_0000006e (S)< const=65"));
                }
            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testGlobalVariable() {

            // ****************************************************************
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: CMP dword ptr [EBP + 0x8],0x2b
            // 00001007: JNZ 0x00001015
            // 00001009: MOV dword ptr [0x00403000],0x43 <== END
            // 00001013: JMP 0x00001025
            // 00001015: CMP dword ptr [EBP + 0x8],0x2c
            // 00001019: JNZ 0x00001025
            // 0000101b: MOV dword ptr [0x00403000],0x2c
            // 00001025: POP EBP
            // 00001026: RET
            // CC's
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: MOV EAX,dword ptr [EBP + 0x8]
            // 00001036: ADD EAX,0x1
            // 00001039: PUSH EAX
            // 0000103a: CALL 0x00001000
            // 0000103f: ADD ESP,0x4
            // 00001042: MOV ECX,dword ptr [EBP + 0x8]
            // 00001045: ADD ECX,0x2
            // 00001048: PUSH ECX
            // 00001049: CALL 0x00001000
            // 0000104e: ADD ESP,0x4
            // 00001051: POP EBP
            // 00001052: RET
            // CC's
            // 00001060: PUSH EBP <== START
            // 00001061: MOV EBP,ESP
            // 00001063: PUSH 0x2a
            // 00001065: CALL 0x00001030
            // 0000106a: ADD ESP,0x4
            // 0000106d: PUSH 0x2b
            // 0000106f: CALL 0x00001030
            // 00001074: ADD ESP,0x4
            // 00001077: XOR EAX,EAX
            // 00001079: POP EBP
            // 0000107a: RET

            final Program program = testEnv.makeTestProgram("Test",
                    "55 8b ec 83 7d 08 2b 75 0c c7 05 00 30 40 00 43 00 00 00 eb 10 83"
                            + "7d 08 2c 75 0a c7 05 00 30 40 00 2c 00 00 00 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc 55 8b ec 8b 45 08 83 c0 01 50 e8 c1 ff ff ff 83 c4 04"
                            + "8b 4d 08 83 c1 02 51 e8 b2 ff ff ff 83 c4 04 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc cc cc cc cc 55 8b ec 6a 2a e8 c6 ff ff ff 83 c4 04 6a"
                            + "2b e8 bc ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1000", "0x1030", "0x1060"}),
                    ProgramBuilder._X86);


            final Address start = program.getAddressFactory().getAddress("0x1060");
            final Address end = program.getAddressFactory().getAddress("0x1009");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);
                Set<HornVariable> globals = hornProgram.getGlobalVariables();

                assertTrue(globals.size() == 2);

                Iterator<HornVariable> itr = globals.iterator();
                if (!itr.hasNext()) {
                    fail("No globals found");
                }
                HornVariable g1 = itr.next();
                HornVariable g2 = itr.next();

                assertTrue(
                        "Memory".equals(g1.getName()) || "DAT_00403000!Test".equals(g1.getName()));
                assertTrue(
                        "Memory".equals(g2.getName()) || "DAT_00403000!Test".equals(g2.getName()));

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testImportedGlobals() {

            // This is a stripped down instance of kernel32.dll that has 9 global variables
            //
            // DAT_10003000 <= Perhaps this is an
            // DWORD_10003fa0 *
            // DWORD_10003fa4 *
            // DWORD_10003fa8 *
            // DWORD_10003fac *
            // DWORD_10003fb0 *
            // DWORD_10003fb4 *
            // DWORD_10003fb8 *
            // DWORD_10003fbc *
            try {
                final List<HighFunction> importFuncList = testEnv.decompileTestProgram(
                        "KERNEL32.DLL",
                        "55 8b ec 51 a1 a0 3f 00 10 8b 0d a0 3f 00 10 89 0c 85 00 30 00 10" +
                                "8b 55 08 89 15 a4 3f 00 10 8b 45 0c a3 a8 3f 00 10 8b 4d 10 89 0d"
                                + "ac 3f 00 10 8b 55 14 89 15 b0 3f 00 10 8b 45 18 a3 b4 3f 00 10 8b"
                                + "4d 1c 89 0d b8 3f 00 10 8b 55 20 89 15 bc 3f 00 10 a1 a0 3f 00 10"
                                + "89 45 fc 8b 0d a0 3f 00 10 83 c1 01 89 0d a0 3f 00 10 8b 45 fc 8b"
                                + "e5 5d c2 1c 00 cc cc cc cc cc cc cc cc cc cc cc cc cc 55 8b ec 51"
                                + "8b 45 08 89 45 fc 8b 4d fc c7 04 8d 00 30 00 10 ff ff ff ff b8 01"
                                + "00 00 00 8b e5 5d c2 04 00",
                        Arrays.asList(new String[] {"0x1000", // CreateFileA
                                "0x1080", // CloseHandle
                                "0x10b0" // OEP
                        }),
                        ProgramBuilder._X86);
                Program p = importFuncList.get(0).getFunction().getProgram();
                tx(p, () -> importFuncList.get(0).getFunction().setName("CreateFileA",
                        SourceType.USER_DEFINED));
                tx(p, () -> importFuncList.get(1).getFunction().setName("CloseHandle",
                        SourceType.USER_DEFINED));

                DummyApiDatabase apiDb = new DummyApiDatabase();

                apiDb.installPreloadedLibrary("KERNEL32.DLL", importFuncList);

                final Program program =
                        testEnv.importTestProgram("msvc32b-fileopen-single.exe");

                final Address entry =
                        program.getAddressFactory().getAddress("0x401000");

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, new ApiSignature(), apiDb);

                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);

                Set<HornVariable> importedGlobals = new HashSet<>();

                for (HornPredicate pred : hornProgram.getPredicates()) {

                    for (HornVariable v : pred.getVariables()) {
                        if (v.getScope() == HornVariable.Scope.Global) {
                            if (v.getVariableName().getProgramId().equals("KERNEL32.DLL")) {
                                importedGlobals.add(v);
                            }
                        }
                    }

                }
                assertTrue(importedGlobals.size() == 8,
                        "Wrong number of imported variables found: "
                                + importedGlobals.size());

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        /**
         * Test that calls and return to APIs are correctly computed
         */
        @Test
        public void testApiCallStartsAndReturns() {
            try {
                final Program program =
                        testEnv.importTestProgram("msvc32b-fileopen-single.exe");

                final Address entry =
                        program.getAddressFactory().getAddress("0x401000");

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, new ApiSignature());

                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);

                Collection<HornClause> createfileCallingClause =
                        hornProgram.getApiCallingClauses("KERNEL32.DLL::CreateFileA");
                Collection<HornClause> createfileReturningClause =
                        hornProgram.getApiReturningClauses("KERNEL32.DLL::CreateFileA");

                assertTrue(createfileCallingClause.size() == 1);
                assertTrue(createfileReturningClause.size() == 1);

                // boolean callClausesOK = false;
                HornClause c = createfileCallingClause.iterator().next();
                assertTrue(c.getName().equals(
                        "KERNEL32.DLL::CREATEFILEA_pre_40101b-KERNEL32.DLL::CREATEFILEA_post_40101b"),
                        "Incorrect calling clause found");

                HornClause r = createfileReturningClause.iterator().next();
                assertTrue(r.getName().equals("KERNEL32.DLL::CREATEFILEA_post_40101b-00401021"),
                        "Incorrect return clause found");


            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testSingleBB() {

            // This prgram has a single basic block

            try {
                final Program program =
                        testEnv.importTestProgram("msvc32b-single-bb.exe");

                Address entry = program.getSymbolTable()
                        .getExternalEntryPointIterator()
                        .next();

                final Address start =
                        program.getAddressFactory().getAddress("0x401030");
                final Address end =
                        program.getAddressFactory().getAddress("0x401042");

                try {

                    Pair<GhiHornEventListener, GhiHornifier> toolPair =
                            testEnv.setUpPathAnalyzer(entry, start, end);

                    GhiHornifier hornifier = toolPair.second;
                    GhiHornEventListener listener = toolPair.first;

                    GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                    cmd.addCommandListener(listener);
                    cmd.applyTo(program);

                    // Wait for an asyncronous response
                    int i = 0;
                    while (i < 10 && listener.isDone() == false) {
                        Thread.sleep(100);
                        ++i;
                    }

                    final GhiHornAnswer ans = listener.getAnswer().get(0);
                    assertTrue(ans != null);
                    assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

                } catch (Exception e) {
                    e.printStackTrace();
                    fail();
                }


            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testSingleBBUnsat() {
            try {
                final Program program =
                        testEnv.importTestProgram("msvc32b-single-bb.exe");

                Address entry = program.getSymbolTable()
                        .getExternalEntryPointIterator()
                        .next();

                final Address start =
                        program.getAddressFactory().getAddress("0x401030");
                final Address end =
                        program.getAddressFactory().getAddress("0x401049");

                try {

                    Pair<GhiHornEventListener, GhiHornifier> toolPair =
                            testEnv.setUpPathAnalyzer(entry, start, end);

                    GhiHornifier hornifier = toolPair.second;
                    GhiHornEventListener listener = toolPair.first;

                    GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                    cmd.addCommandListener(listener);
                    cmd.applyTo(program);

                    // Wait for an asyncronous response
                    int i = 0;
                    while (i < 10 && listener.isDone() == false) {
                        Thread.sleep(100);
                        ++i;
                    }

                    final GhiHornAnswer ans = listener.getAnswer().get(0);
                    assertTrue(ans != null);
                    assertTrue(ans.status == GhiHornFixedpointStatus.Unsatisfiable);

                } catch (Exception e) {
                    e.printStackTrace();
                    fail();
                }


            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testProgramEntryPredicate() {
            // ****************************************************************
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: CMP dword ptr [EBP + 0x8],0x2b
            // 00001007: JNZ 0x00001015
            // 00001009: MOV dword ptr [0x00403000],0x43 <== END
            // 00001013: JMP 0x00001025
            // 00001015: CMP dword ptr [EBP + 0x8],0x2c
            // 00001019: JNZ 0x00001025
            // 0000101b: MOV dword ptr [0x00403000],0x2c
            // 00001025: POP EBP
            // 00001026: RET
            // CC's
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: MOV EAX,dword ptr [EBP + 0x8]
            // 00001036: ADD EAX,0x1
            // 00001039: PUSH EAX
            // 0000103a: CALL 0x00001000
            // 0000103f: ADD ESP,0x4
            // 00001042: MOV ECX,dword ptr [EBP + 0x8]
            // 00001045: ADD ECX,0x2
            // 00001048: PUSH ECX
            // 00001049: CALL 0x00001000
            // 0000104e: ADD ESP,0x4
            // 00001051: POP EBP
            // 00001052: RET
            // CC's
            // 00001060: PUSH EBP <== START
            // 00001061: MOV EBP,ESP
            // 00001063: PUSH 0x2a
            // 00001065: CALL 0x00001030
            // 0000106a: ADD ESP,0x4
            // 0000106d: PUSH 0x2b
            // 0000106f: CALL 0x00001030
            // 00001074: ADD ESP,0x4
            // 00001077: XOR EAX,EAX
            // 00001079: POP EBP
            // 0000107a: RET

            final Program program = testEnv.buildTestProgram("Test",
                    "55 8b ec 83 7d 08 2b 75 0c c7 05 00 30 40 00 43 00 00 00 eb 10 83"
                            + "7d 08 2c 75 0a c7 05 00 30 40 00 2c 00 00 00 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc 55 8b ec 8b 45 08 83 c0 01 50 e8 c1 ff ff ff 83 c4 04"
                            + "8b 4d 08 83 c1 02 51 e8 b2 ff ff ff 83 c4 04 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc cc cc cc cc 55 8b ec 6a 2a e8 c6 ff ff ff 83 c4 04 6a"
                            + "2b e8 bc ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1000", "0x1030", "0x1060"}),
                    ProgramBuilder._X86);


            try {

                final Address start =
                        program.getAddressFactory().getAddress("0x1060");
                final Address end =
                        program.getAddressFactory().getAddress("0x1060");
                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);

                Optional<HornPredicate> optPred = hornProgram.getEntryPredicate();

                assertTrue(optPred.isPresent());
                HornPredicate entryPred = optPred.get();

                assertTrue(entryPred.isEntry());
                // This is the entry point predicate for this program.
                assertTrue(entryPred.toString()
                        .equals("FUN_00001060_pre_1060(DAT_00403000!Test,Memory)"));

            } catch (Exception e) {
                fail(e.getMessage());
            }
        }


        @Test
        public void testGlobalVariableInPredicates() {
            // ****************************************************************
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: CMP dword ptr [EBP + 0x8],0x2b
            // 00001007: JNZ 0x00001015
            // 00001009: MOV dword ptr [0x00403000],0x43 <== END
            // 00001013: JMP 0x00001025
            // 00001015: CMP dword ptr [EBP + 0x8],0x2c
            // 00001019: JNZ 0x00001025
            // 0000101b: MOV dword ptr [0x00403000],0x2c
            // 00001025: POP EBP
            // 00001026: RET
            // CC's
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: MOV EAX,dword ptr [EBP + 0x8]
            // 00001036: ADD EAX,0x1
            // 00001039: PUSH EAX
            // 0000103a: CALL 0x00001000
            // 0000103f: ADD ESP,0x4
            // 00001042: MOV ECX,dword ptr [EBP + 0x8]
            // 00001045: ADD ECX,0x2
            // 00001048: PUSH ECX
            // 00001049: CALL 0x00001000
            // 0000104e: ADD ESP,0x4
            // 00001051: POP EBP
            // 00001052: RET
            // CC's
            // 00001060: PUSH EBP <== START
            // 00001061: MOV EBP,ESP
            // 00001063: PUSH 0x2a
            // 00001065: CALL 0x00001030
            // 0000106a: ADD ESP,0x4
            // 0000106d: PUSH 0x2b
            // 0000106f: CALL 0x00001030
            // 00001074: ADD ESP,0x4
            // 00001077: XOR EAX,EAX
            // 00001079: POP EBP
            // 0000107a: RET

            final Program program = testEnv.buildTestProgram("Test",
                    "55 8b ec 83 7d 08 2b 75 0c c7 05 00 30 40 00 43 00 00 00 eb 10 83"
                            + "7d 08 2c 75 0a c7 05 00 30 40 00 2c 00 00 00 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc 55 8b ec 8b 45 08 83 c0 01 50 e8 c1 ff ff ff 83 c4 04"
                            + "8b 4d 08 83 c1 02 51 e8 b2 ff ff ff 83 c4 04 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc cc cc cc cc 55 8b ec 6a 2a e8 c6 ff ff ff 83 c4 04 6a"
                            + "2b e8 bc ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1000", "0x1030", "0x1060"}),
                    ProgramBuilder._X86);

            final Address start =
                    program.getAddressFactory().getAddress("0x1060");
            final Address end =
                    program.getAddressFactory().getAddress("0x1009");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);

                // Test that the two global variables are present in every predicate
                for (HornPredicate pred : hornProgram.getPredicates()) {
                    boolean foundMem = false, foundDat = false;
                    for (HornVariable v : pred.getVariables()) {
                        if (v.getScope() == HornVariable.Scope.Global) {
                            if ("Memory".equals(v.getName())) {
                                foundMem = true;
                            } else if ("DAT_00403000!Test".equals(v.getName())) {
                                foundDat = true;
                            }
                        }
                    }
                    assertTrue(foundDat && foundMem,
                            "Global variables not passed to all predicates");
                }

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        /**
         * Test to make sure that function parameters are passed to each block
         */
        @Test
        public void testFuncInstances() {
            // ****************************************************************
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: CMP dword ptr [EBP + 0x8],0x2b
            // 00001007: JNZ 0x00001015
            // 00001009: MOV dword ptr [0x00403000],0x43
            // 00001013: JMP 0x00001025
            // 00001015: CMP dword ptr [EBP + 0x8],0x2c
            // 00001019: JNZ 0x00001025
            // 0000101b: MOV dword ptr [0x00403000],0x2c
            // 00001025: POP EBP
            // 00001026: RET <== END
            // CC's
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: MOV EAX,dword ptr [EBP + 0x8]
            // 00001036: ADD EAX,0x1
            // 00001039: PUSH EAX
            // 0000103a: CALL 0x00001000
            // 0000103f: ADD ESP,0x4
            // 00001042: MOV ECX,dword ptr [EBP + 0x8]
            // 00001045: ADD ECX,0x2
            // 00001048: PUSH ECX
            // 00001049: CALL 0x00001000
            // 0000104e: ADD ESP,0x4
            // 00001051: POP EBP
            // 00001052: RET
            // CC's
            // 00001060: PUSH EBP <== START
            // 00001061: MOV EBP,ESP
            // 00001063: PUSH 0x2a
            // 00001065: CALL 0x00001030
            // 0000106a: ADD ESP,0x4
            // 0000106d: PUSH 0x2b
            // 0000106f: CALL 0x00001030
            // 00001074: ADD ESP,0x4
            // 00001077: XOR EAX,EAX
            // 00001079: POP EBP
            // 0000107a: RET

            final Program program = testEnv.buildTestProgram("Test",
                    "55 8b ec 83 7d 08 2b 75 0c c7 05 00 30 40 00 43 00 00 00 eb 10 83"
                            + "7d 08 2c 75 0a c7 05 00 30 40 00 2c 00 00 00 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc 55 8b ec 8b 45 08 83 c0 01 50 e8 c1 ff ff ff 83 c4 04"
                            + "8b 4d 08 83 c1 02 51 e8 b2 ff ff ff 83 c4 04 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc cc cc cc cc 55 8b ec 6a 2a e8 c6 ff ff ff 83 c4 04 6a"
                            + "2b e8 bc ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1000", "0x1030", "0x1060"}),
                    ProgramBuilder._X86);

            final Address start =
                    program.getAddressFactory().getAddress("0x1060");
            final Address end =
                    program.getAddressFactory().getAddress("0x1026");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);

                Map<String, HornFunctionInstance> funcInstMap = hornProgram.getFunctionInstances();
                // 4 called functions + entry
                assertTrue(funcInstMap.size() == 5);

                // The entry is not called
                HornFunctionInstance x = funcInstMap.get("1060");
                assertTrue(x.getXrefAddress() == Address.NO_ADDRESS);

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testValuePropogation() {

            // 100: PUSH RBP
            // 1001: MOV RBP,RSP
            // 1004: MOV dword ptr [RBP + -0x4],0x0
            // 100b: MOV dword ptr [RBP + -0x8],EDI
            // 100e: MOV qword ptr [RBP + -0x10],RSI
            // 1012: MOV dword ptr [RBP + -0x14],0x1
            // 1019: CMP dword ptr [0x00001090],0x42
            // 1020: JLE 0x00001032
            // 1026: MOV dword ptr [RBP + -0x14],0x2
            // 102d: JMP 0x00001039
            // 1032: MOV dword ptr [RBP + -0x14],0x3
            // 1039: MOV EAX,dword ptr [RBP + -0x14]
            // 103c: POP RBP
            // 103d: RET

            HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 c7 45 fc 00 00 00 00 89 7d f8 48 89 75"
                            + "f0 c7 45 ec 01 00 00 00 83 3d 70 00 00 00 42 0f 8e"
                            + "0c 00 00 00 c7 45 ec 02 00 00 00 e9 07 00 00 00 c7"
                            + "45 ec 03 00 00 00 8b 45 ec 5d c3 90 90",
                    ProgramBuilder._X64);

            try {

                Program program = hf.getFunction().getProgram();

                Address start = hf.getFunction().getBody().getMinAddress();
                Address end = hf.getFunction().getBody().getMaxAddress();
                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornifier hornifier = toolPair.second;
                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);

                // These clauses pass actual values to rules, so test to see if that is working
                // in this clause,
                // 00001026-00001039
                // (|00001039_1000| LAB_00001090 Memory #x0000000000000002 uVar180@FUN_00001000)
                // <- (|00001026_1000| LAB_00001090 Memory local_1c@FUN_00001000) && true
                //

                // 00001032-00001039
                // (|00001039_1000| LAB_00001090 Memory #x0000000000000003 uVar180@FUN_00001000)
                // <- (|00001032_1000| LAB_00001090 Memory local_1c@FUN_00001000) && true
                //

                for (HornClause clause : hornProgram.getClauses()) {
                    HornRuleExpr rX = clause.instantiate(ctx);
                    if (clause.getName().equals("00001026-00001039")) {
                        // (|00001039_1000| LAB_00001090 Memory #x0000000000000002
                        // uVar180@FUN_00001000)
                        // check for the 2
                        String val = rX.getHeadExpr().getArgs()[2].toString();
                        assertTrue(val.equals("2"), val);
                    }

                    else if (clause.getName().equals("00001032-00001039")) {
                        // (|00001039_1000| LAB_00001090 Memory #x0000000000000003
                        // uVar180@FUN_00001000)
                        // check for the 3
                        String val = rX.getHeadExpr().getArgs()[2].toString();
                        assertTrue(val.equals("3"), val);
                    }

                }
            } catch (Exception e) {
                fail(e.getMessage());
            }
        }
    }


    @Nested
    @DisplayName("PathAnalyzer Tests")
    class PathAnalyzerTests {
        @Test
        public void testPathAnalyzerSat() {

            // ************************************************************************
            //
            // The bytestring results in this function:
            //
            // 00001000: PUSH RBP
            // 00001001: MOV RBP,RSP
            // 00001004: MOV dword ptr [RBP + -0x4],0x0
            // 0000100b: CMP dword ptr [0x00001100],0x64
            // 00001012: JLE 0x00001024
            // 00001018: MOV dword ptr [RBP + -0x8],0x100
            // 0000101f: JMP 0x000010ac
            // 00001024: CMP dword ptr [0x00001100],0x32
            // 0000102b: JLE 0x0000104a
            // 00001031: CMP dword ptr [0x00001100],0x64
            // 00001038: JGE 0x0000104a
            // 0000103e: MOV dword ptr [RBP + -0x8],0x101
            // 00001045: JMP 0x000010a7
            // 0000104a: CMP dword ptr [0x00001100],0x0
            // 00001051: JLE 0x00001070
            // 00001057: CMP dword ptr [0x00001100],0x32
            // 0000105e: JGE 0x00001070
            // 00001064: MOV dword ptr [RBP + -0x8],0x101
            // 0000106b: JMP 0x000010a2
            // 00001070: CMP dword ptr [0x00001100],0x32
            // 00001077: JLE 0x00001096
            // 0000107d: CMP dword ptr [0x00001100],0xa
            // 00001084: JGE 0x00001096
            // 0000108a: MOV dword ptr [RBP + -0x8],0x102
            // 00001091: JMP 0x0000109d
            // 00001096: MOV dword ptr [RBP + -0x8],0x14
            // 0000109d: JMP 0x000010a2
            // 000010a2: JMP 0x000010a7
            // 000010a7: JMP 0x000010ac
            // 000010ac: MOV EAX,dword ptr [RBP + -0x8]
            // 000010af: POP RBP
            // 000010b0: RET

            // ************************************************************************

            final HighFunction hf = testEnv
                    .buildTestFunction("Test",
                            "55 48 89 e5 c7 45 fc 00 00 00 00 83 3d ee 00 00 00 64 0f 8e 0c 00 00 00"
                                    + "c7 45 f8 00 01 00 00 e9 88 00 00 00 83 3d d5 00 00 00 32 0f 8e 19 00 00"
                                    + "00 83 3d c8 00 00 00 64 0f 8d 0c 00 00 00 c7 45 f8 01 01 00 00 e9 5d 00"
                                    + "00 00 83 3d af 00 00 00 00 0f 8e 19 00 00 00 83 3d a2 00 00 00 32 0f 8d"
                                    + "0c 00 00 00 c7 45 f8 01 01 00 00 e9 32 00 00 00 83 3d 89 00 00 00 32 0f"
                                    + "8e 19 00 00 00 83 3d 7c 00 00 00 0a 0f 8d 0c 00 00 00 c7 45 f8 02 01 00"
                                    + "00 e9 07 00 00 00 c7 45 f8 14 00 00 00 e9 00 00 00 00 e9 00 00 00 00 e9"
                                    + "00 00 00 00 8b 45 f8 5d c3 90 90 90",
                            ProgramBuilder._X64);

            Program program = hf.getFunction().getProgram();

            final Address start = hf.getFunction().getEntryPoint();
            final Address end = program.getAddressFactory().getAddress("0x1096");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);

                GhiHornifier hornifier = toolPair.second;
                GhiHornEventListener listener = toolPair.first;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                // Wait for an asyncronous response
                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }

                final GhiHornAnswer ans = listener.getAnswer().get(0);
                assertTrue(ans != null);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testRetvalPath() {

            // ************************************************************************
            //
            // The bytestring results in this function:
            //
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: MOV EAX,dword ptr [EBP + 0x8]
            // 00001006: AND EAX,0x80000000
            // 0000100b: JNS 0x00001012
            // 0000100d: DEC EAX
            // 0000100e: OR EAX,0xffffffff
            // 00001011: INC EAX
            // 00001012: TEST EAX,EAX
            // 00001014: JNZ 0x00001020
            // 00001016: MOV EAX,dword ptr [EBP + 0x8]
            // 00001019: ADD EAX,0x1
            // 0000101c: JMP 0x00001026
            // 0000101e: JMP 0x00001026
            // 00001020: MOV EAX,dword ptr [EBP + 0x8]
            // 00001023: ADD EAX,0x2
            // 00001026: POP EBP
            // 00001027: RET
            //
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: PUSH ECX
            // 00001034: MOV EAX,dword ptr [EBP + 0x8]
            // 00001037: ADD EAX,0x1
            // 0000103a: PUSH EAX
            // 0000103b: CALL 0x00001000
            // 00001040: ADD ESP,0x4
            // 00001043: MOV dword ptr [EBP + -0x4],EAX
            // 00001046: CMP dword ptr [EBP + -0x4],0x42
            // 0000104a: JNZ 0x00001058
            // 0000104c: MOV dword ptr [0x00403000],0x1
            // 00001056: JMP 0x00001062
            // 00001058: MOV dword ptr [0x00403000],0x3
            // 00001062: MOV ESP,EBP
            // 00001064: POP EBP
            // 00001065: RET
            //
            // 00001070: PUSH EBP
            // 00001071: MOV EBP,ESP
            // 00001073: MOV EAX,dword ptr [EBP + 0x8]
            // 00001076: PUSH EAX
            // 00001077: CALL 0x00001030
            // 0000107c: ADD ESP,0x4
            // 0000107f: XOR EAX,EAX
            // 00001081: POP EBP
            // 00001082: RET
            //
            // The key is that the return value at address 00001043 is used in a choice

            final Program program = testEnv.buildTestProgram("Test",
                    "55 8b ec 8b 45 08 25 00 00 00 80 79 05 48 83 c8 ff 40 85"
                            + "c0 75 0a 8b 45 08 83 c0 01 eb 08 eb 06 8b 45 08 83 c0 02"
                            + "5d c3 cc cc cc cc cc cc cc cc 55 8b ec 51 8b 45 08 83 c0"
                            + "01 50 e8 c0 ff ff ff 83 c4 04 89 45 fc 83 7d fc 42 75 0c"
                            + "c7 05 00 30 40 00 01 00 00 00 eb 0a c7 05 00 30 40 00 03"
                            + "00 00 00 8b e5 5d c3 cc cc cc cc cc cc cc cc cc cc"
                            + "55 8b ec 8b 45 08 50 e8 b4 ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1070", "0x1030", "0x1000"}),
                    ProgramBuilder._X86);


            final Address start = program.getAddressFactory().getAddress("0x1070");
            final Address end = program.getAddressFactory().getAddress("0x104c");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);

                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                // Wait for an asyncronous response
                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }

                GhiHornAnswer ans = listener.getAnswer().get(0);
                assertTrue(ans != null);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);
                List<GhiHornAnswerGraphVertex> vtxList = ans.answerGraph.getVerticesInPreOrder();

                // Check specific values assigned
                // the initial value of the param_1 should be 64;

                GhiHornAnswerGraphVertex vertex0 = vtxList.get(0);
                GhiHornSatAttributes satAttrs0 = (GhiHornSatAttributes) vertex0.getAttributes();
                for (var entry : satAttrs0.getValueMap().entrySet()) {
                    if (entry.getKey().getName().equals("param_1@FUN_00001070")) {
                        assertTrue(entry.getValue().equals("64"));
                    }
                }

                // The intermediate value is 65 (param_1 + 1)

                GhiHornAnswerGraphVertex vertex3 = vtxList.get(3);
                GhiHornSatAttributes satAttrs3 = (GhiHornSatAttributes) vertex3.getAttributes();
                // the initial value of the param_1 should be 65;
                for (var entry : satAttrs3.getValueMap().entrySet()) {
                    if (entry.getKey().getName().equals("param_1@FUN_00001000")) {
                        assertTrue(entry.getValue().equals("65"));
                    }
                }

                // The final returned value should be 66 (0x42)

                GhiHornAnswerGraphVertex vertex4 = vtxList.get(4);
                GhiHornSatAttributes satAttrs4 = (GhiHornSatAttributes) vertex4.getAttributes();
                // the final value of the iVar1 should be 66;
                for (var entry : satAttrs4.getValueMap().entrySet()) {
                    if (entry.getKey().getName().equals("iVar1@FUN_00001030")) {
                        assertTrue(entry.getValue().equals("66"));
                    }
                }

            } catch (

            Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testSatPath() {

            // ************************************************************************
            //
            // The bytestring results in this function:
            //
            // 00001000: PUSH RBP
            // 00001001: MOV RBP,RSPN
            // 00001004: MOV dword ptr [RBP + -0x4],0x0
            // 0000100b: CMP dword ptr [0x00001100],0x64
            // 00001012: JLE 0x00001024
            // 00001018: MOV dword ptr [RBP + -0x8],0x100
            // 0000101f: JMP 0x000010ac
            // 00001024: CMP dword ptr [0x00001100],0x32
            // 0000102b: JLE 0x0000104a
            // 00001031: CMP dword ptr [0x00001100],0x64
            // 00001038: JGE 0x0000104a
            // 0000103e: MOV dword ptr [RBP + -0x8],0x101
            // 00001045: JMP 0x000010a7
            // 0000104a: CMP dword ptr [0x00001100],0x0
            // 00001051: JLE 0x00001070
            // 00001057: CMP dword ptr [0x00001100],0x32
            // 0000105e: JGE 0x00001070
            // 00001064: MOV dword ptr [RBP + -0x8],0x101
            // 0000106b: JMP 0x000010a2
            // 00001070: CMP dword ptr [0x00001100],0x32
            // 00001077: JLE 0x00001096
            // 0000107d: CMP dword ptr [0x00001100],0xa
            // 00001084: JGE 0x00001096
            // 0000108a: MOV dword ptr [RBP + -0x8],0x102
            // 00001091: JMP 0x0000109d
            // 00001096: MOV dword ptr [RBP + -0x8],0x14
            // 0000109d: JMP 0x000010a2
            // 000010a2: JMP 0x000010a7
            // 000010a7: JMP 0x000010ac
            // 000010ac: MOV EAX,dword ptr [RBP + -0x8]
            // 000010af: POP RBP
            // 000010b0: RET

            // ************************************************************************

            final HighFunction hf = testEnv
                    .buildTestFunction("Test",
                            "55 48 89 e5 c7 45 fc 00 00 00 00 83 3d ee 00 00 00 64 0f 8e 0c 00 00 00"
                                    + "c7 45 f8 00 01 00 00 e9 88 00 00 00 83 3d d5 00 00 00 32 0f 8e 19 00 00"
                                    + "00 83 3d c8 00 00 00 64 0f 8d 0c 00 00 00 c7 45 f8 01 01 00 00 e9 5d 00"
                                    + "00 00 83 3d af 00 00 00 00 0f 8e 19 00 00 00 83 3d a2 00 00 00 32 0f 8d"
                                    + "0c 00 00 00 c7 45 f8 01 01 00 00 e9 32 00 00 00 83 3d 89 00 00 00 32 0f"
                                    + "8e 19 00 00 00 83 3d 7c 00 00 00 0a 0f 8d 0c 00 00 00 c7 45 f8 02 01 00"
                                    + "00 e9 07 00 00 00 c7 45 f8 14 00 00 00 e9 00 00 00 00 e9 00 00 00 00 e9"
                                    + "00 00 00 00 8b 45 f8 5d c3 90 90 90",
                            ProgramBuilder._X64);

            Program program = hf.getFunction().getProgram();

            final Address start = hf.getFunction().getEntryPoint();
            final Address end =
                    program.getAddressFactory().getAddress("0x1096");

            try {
                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                GhiHornAnswer ans = listener.getAnswer().get(0);
                assertTrue(ans != null);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

                List<GhiHornAnswerGraphVertex> path = ans.answerGraph.getVerticesInPreOrder();

                // The correct path is:
                //
                // entry
                // .00001000_1000 (1)
                // ..00001024_1000 (2)
                // ...0000104a_1000 (3)
                // ....00001070_1000 (4)
                // .....00001096_1000 (5)
                // ......goal (6)
                assertTrue(path.get(0).getVertexName().equals("start"), "Incorrect start");
                assertTrue(path.get(1).getVertexName().equals("FUN_00001000_pre_1000"),
                        "Incorrect path: " + path.get(1));
                assertTrue(path.get(2).getVertexName().equals("00001000_1000"),
                        "Incorrect path: " + path.get(2));
                assertTrue(path.get(3).getVertexName().equals("00001024_1000"),
                        "Incorrect path: " + path.get(3));
                assertTrue(path.get(4).getVertexName().equals("0000104a_1000"),
                        "Incorrect path: " + path.get(4));
                assertTrue(path.get(5).getVertexName().equals("00001070_1000"),
                        "Incorrect path: " + path.get(5));
                assertTrue(path.get(6).getVertexName().equals("00001096_1000"),
                        "Incorrect path: " + path.get(6));
                assertTrue(path.get(7).getVertexName().equals("goal"), "Incorrect goal");

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testPathAnalyzerUnsat() {

            // ****************************************************************
            //
            // local_1c = 0;
            // local_20 = 0;
            // while (local_20 < param_1) {
            // local_1c = local_1c + 2;
            // local_20 = local_20 + 1;
            // }
            // if (local_1c == 43) {
            // __test = 0xd34db33f; <== Not possible because local_1c is even
            // }
            // return 0;
            //
            // 00001000: PUSH RBP
            // 00001001: MOV RBP,RSP
            // 00001004: MOV dword ptr [RBP + -0x4],0x0
            // 0000100b: MOV dword ptr [RBP + -0x8],EDI
            // 0000100e: MOV qword ptr [RBP + -0x10],RSI
            // 00001012: MOV dword ptr [RBP + -0x14],0x0
            // 00001019: MOV dword ptr [RBP + -0x18],0x0
            // 00001020: MOV EAX,dword ptr [RBP + -0x18]
            // 00001023: CMP EAX,dword ptr [RBP + -0x8]
            // 00001026: JGE 0x00001043
            // 0000102c: MOV EAX,dword ptr [RBP + -0x14]
            // 0000102f: ADD EAX,0x2
            // 00001032: MOV dword ptr [RBP + -0x14],EAX
            // 00001035: MOV EAX,dword ptr [RBP + -0x18]
            // 00001038: ADD EAX,0x1
            // 0000103b: MOV dword ptr [RBP + -0x18],EAX
            // 0000103e: JMP 0x00001020
            // 00001043: CMP dword ptr [RBP + -0x14],0x2b
            // 00001047: JNZ 0x00001057
            // 0000104d: MOV dword ptr [0x000010b0],0xd34db33f <== impossible
            // 00001057: MOV EAX,dword ptr [RBP + -0x4]
            // 0000105a: POP RBP
            // 0000105b: RET

            final HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 c7 45 fc 00 00 00 00 89 7d f8 48 89 75 f0 c7 45 ec 00"
                            + "00 00 00 c7 45 e8 00 00 00 00 8b 45 e8 3b 45 f8 0f 8d 17 00 00 00"
                            + "8b 45 ec 83 c0 02 89 45 ec 8b 45 e8 83 c0 01 89 45 e8 e9 dd ff ff"
                            + "ff 83 7d ec 2b 0f 85 0a 00 00 00 c7 05 59 00 00 00 3f b3 4d d3 8b 45 fc 5d c3",
                    ProgramBuilder._X64);

            Program program = hf.getFunction().getProgram();

            final Address start = hf.getFunction().getEntryPoint();
            final Address end =
                    program.getAddressFactory().getAddress("0x104d");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                GhiHornAnswer ans = listener.getAnswer().get(0);

                assertTrue(ans.status == GhiHornFixedpointStatus.Unsatisfiable);

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        /**
         * Test specific unsat conditions
         */
        @Test
        public void testMsvc32bUnsatConditions() {

            // ****************************************************************
            //
            // local_1c = 0;
            // local_20 = 0;
            // while (local_20 < param_1) {
            // local_1c = local_1c + 2;
            // local_20 = local_20 + 1;
            // }
            // if (local_1c == 43) {
            // __test = 0xd34db33f; <== Not possible because local_1c is even
            // }
            // return 0;
            //
            // 00001000: PUSH RBP
            // 00001001: MOV RBP,RSP
            // 00001004: MOV dword ptr [RBP + -0x4],0x0
            // 0000100b: MOV dword ptr [RBP + -0x8],EDI
            // 0000100e: MOV qword ptr [RBP + -0x10],RSI
            // 00001012: MOV dword ptr [RBP + -0x14],0x0
            // 00001019: MOV dword ptr [RBP + -0x18],0x0
            // 00001020: MOV EAX,dword ptr [RBP + -0x18]
            // 00001023: CMP EAX,dword ptr [RBP + -0x8]
            // 00001026: JGE 0x00001043
            // 0000102c: MOV EAX,dword ptr [RBP + -0x14]
            // 0000102f: ADD EAX,0x2
            // 00001032: MOV dword ptr [RBP + -0x14],EAX
            // 00001035: MOV EAX,dword ptr [RBP + -0x18]
            // 00001038: ADD EAX,0x1
            // 0000103b: MOV dword ptr [RBP + -0x18],EAX
            // 0000103e: JMP 0x00001020
            // 00001043: CMP dword ptr [RBP + -0x14],0x2b
            // 00001047: JNZ 0x00001057
            // 0000104d: MOV dword ptr [0x000010b0],0xd34db33f <== impossible
            // 00001057: MOV EAX,dword ptr [RBP + -0x4]
            // 0000105a: POP RBP
            // 0000105b: RET

            final HighFunction hf = testEnv.buildTestFunction("Test",
                    "55 48 89 e5 c7 45 fc 00 00 00 00 89 7d f8 48 89 75 f0 c7 45 ec 00"
                            + "00 00 00 c7 45 e8 00 00 00 00 8b 45 e8 3b 45 f8 0f 8d 17 00 00 00"
                            + "8b 45 ec 83 c0 02 89 45 ec 8b 45 e8 83 c0 01 89 45 e8 e9 dd ff ff"
                            + "ff 83 7d ec 2b 0f 85 0a 00 00 00 c7 05 59 00 00 00 3f b3 4d d3 8b 45 fc 5d c3",
                    ProgramBuilder._X64);

            Program program = hf.getFunction().getProgram();

            final Address start = hf.getFunction().getEntryPoint();
            final Address end =
                    program.getAddressFactory().getAddress("0x104d");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                GhiHornAnswer ans = listener.getAnswer().get(0);

                assertTrue(ans.status == GhiHornFixedpointStatus.Unsatisfiable);

                // The returned path is:
                //
                // 0: start: true
                // 1: FUN_00001000_pre_1000: true
                // 2: 00001000_1000: true
                // 3: 00001020_1000: (not (= ((_ extract 0 0) (local_1c)) #b1))
                // 4: 00001043_1000: (not (= ((_ extract 0 0) (local_1c)) #b1))
                // 5: 00001057_1000: true
                // 6: FUN_00001000_post_1000: (= (uVar475) #x0000000000000000)
                // 7: 0000104d_1000: false
                // 8: goal:

                final List<GhiHornAnswerGraphVertex> path = ans.answerGraph.getVerticesInPreOrder();
                assertTrue(path.size() == 10);

                // Check each
                for (GhiHornAnswerGraphVertex vtx : path) {

                    GhiHornUnsatAttributes unsatAttributes =
                            (GhiHornUnsatAttributes) vtx.getAttributes();

                    if (unsatAttributes.getVertexName().equals("start")) {
                        assertTrue("start: true".equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("FUN_00001000_pre_1000")) {
                        assertTrue(
                                "FUN_00001000_pre_1000: true".equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("00001000_1000")) {
                        assertTrue("00001000_1000: true".equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("00001020_1000")) {
                        assertTrue("00001020_1000: (not (= ((_ extract 0 0) (local_1c)) #b1))"
                                .equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("00001043_1000")) {
                        assertTrue("00001043_1000: (not (= ((_ extract 0 0) (local_1c)) #b1))"
                                .equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("0000104d_1000")) {
                        assertTrue("0000104d_1000: false".equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("00001057_1000")) {
                        assertTrue("00001057_1000: true".equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("FUN_00001000_post_1000")) {
                        if (GhidraDI.isAtLeastGhidraMinorVersion("10.2.0")) {
                            // TODO: check if this is correct for Ghidra 10.2+
                            //assertTrue("FUN_00001000_post_1000: true".equals(unsatAttributes.toString()));
                        } else {
                            //assertTrue("FUN_00001000_post_1000: (= (uVar475) #x0000000000000000)"
                                //.equals(unsatAttributes.toString()));
                        }
                    } else if (unsatAttributes.getVertexName().equals("goal")) {
                        //assertTrue("goal".equals(unsatAttributes.toString()));
                    } else if (unsatAttributes.getVertexName().equals("0000102c_1000")) {
                        //assertTrue("0000102c_1000: (not (= ((_ extract 0 0) (local_1c)) #b1))"
                                //.equals(unsatAttributes.toString()));
                    }
                }

            } catch (

            Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testMsvc32bMultiFuncSat() {

            // ****************************************************************
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: CMP dword ptr [EBP + 0x8],0x2b
            // 00001007: JNZ 0x00001015
            // 00001009: MOV dword ptr [0x00403000],0x43 <== END
            // 00001013: JMP 0x00001025
            // 00001015: CMP dword ptr [EBP + 0x8],0x2c
            // 00001019: JNZ 0x00001025
            // 0000101b: MOV dword ptr [0x00403000],0x2c
            // 00001025: POP EBP
            // 00001026: RET
            // CC's
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: MOV EAX,dword ptr [EBP + 0x8]
            // 00001036: ADD EAX,0x1
            // 00001039: PUSH EAX
            // 0000103a: CALL 0x00001000
            // 0000103f: ADD ESP,0x4
            // 00001042: MOV ECX,dword ptr [EBP + 0x8]
            // 00001045: ADD ECX,0x2
            // 00001048: PUSH ECX
            // 00001049: CALL 0x00001000
            // 0000104e: ADD ESP,0x4
            // 00001051: POP EBP
            // 00001052: RET
            // CC's
            // 00001060: PUSH EBP <== START
            // 00001061: MOV EBP,ESP
            // 00001063: PUSH 0x2a
            // 00001065: CALL 0x00001030
            // 0000106a: ADD ESP,0x4
            // 0000106d: PUSH 0x2b
            // 0000106f: CALL 0x00001030
            // 00001074: ADD ESP,0x4
            // 00001077: XOR EAX,EAX
            // 00001079: POP EBP
            // 0000107a: RET

            final Program program = testEnv.buildTestProgram("Test",
                    "55 8b ec 83 7d 08 2b 75 0c c7 05 00 30 40 00 43 00 00 00 eb 10 83"
                            + "7d 08 2c 75 0a c7 05 00 30 40 00 2c 00 00 00 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc 55 8b ec 8b 45 08 83 c0 01 50 e8 c1 ff ff ff 83 c4 04"
                            + "8b 4d 08 83 c1 02 51 e8 b2 ff ff ff 83 c4 04 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc cc cc cc cc 55 8b ec 6a 2a e8 c6 ff ff ff 83 c4 04 6a"
                            + "2b e8 bc ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1000", "0x1030", "0x1060"}),
                    ProgramBuilder._X86);

            final Address start =
                    program.getAddressFactory().getAddress("0x1060");
            final Address end =
                    program.getAddressFactory().getAddress("0x1009");
            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                GhiHornAnswer ans = listener.getAnswer().get(0);
                assertTrue(ans != null);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testMsvc32bMultiFuncSatPath() {

            // ****************************************************************
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: CMP dword ptr [EBP + 0x8],0x2b
            // 00001007: JNZ 0x00001015
            // 00001009: MOV dword ptr [0x00403000],0x43 <== END
            // 00001013: JMP 0x00001025
            // 00001015: CMP dword ptr [EBP + 0x8],0x2c
            // 00001019: JNZ 0x00001025
            // 0000101b: MOV dword ptr [0x00403000],0x2c
            // 00001025: POP EBP
            // 00001026: RET
            // CC's
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: MOV EAX,dword ptr [EBP + 0x8]
            // 00001036: ADD EAX,0x1
            // 00001039: PUSH EAX
            // 0000103a: CALL 0x00001000
            // 0000103f: ADD ESP,0x4
            // 00001042: MOV ECX,dword ptr [EBP + 0x8]
            // 00001045: ADD ECX,0x2
            // 00001048: PUSH ECX
            // 00001049: CALL 0x00001000
            // 0000104e: ADD ESP,0x4
            // 00001051: POP EBP
            // 00001052: RET
            // CC's
            // 00001060: PUSH EBP <== START
            // 00001061: MOV EBP,ESP
            // 00001063: PUSH 0x2a
            // 00001065: CALL 0x00001030
            // 0000106a: ADD ESP,0x4
            // 0000106d: PUSH 0x2b
            // 0000106f: CALL 0x00001030
            // 00001074: ADD ESP,0x4
            // 00001077: XOR EAX,EAX
            // 00001079: POP EBP
            // 0000107a: RET

            final Program program = testEnv.buildTestProgram("Test",
                    "55 8b ec 83 7d 08 2b 75 0c c7 05 00 30 40 00 43 00 00 00 eb 10 83"
                            + "7d 08 2c 75 0a c7 05 00 30 40 00 2c 00 00 00 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc 55 8b ec 8b 45 08 83 c0 01 50 e8 c1 ff ff ff 83 c4 04"
                            + "8b 4d 08 83 c1 02 51 e8 b2 ff ff ff 83 c4 04 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc cc cc cc cc 55 8b ec 6a 2a e8 c6 ff ff ff 83 c4 04 6a"
                            + "2b e8 bc ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1000", "0x1030", "0x1060"}),
                    ProgramBuilder._X86);

            final Address start =
                    program.getAddressFactory().getAddress("0x1060");
            final Address end =
                    program.getAddressFactory().getAddress("0x1009");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                GhiHornAnswer ans = listener.getAnswer().get(0);
                assertTrue(ans != null);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

                final List<GhiHornAnswerGraphVertex> path = ans.answerGraph.getVerticesInPreOrder();

                // The correct path is:
                //
                // 00001060_1060
                // .FUN_00001030_pre_1065 (1)
                // ..00001030_1065 (2)
                // ...FUN_00001000_pre_103a (3)
                // ....00001000_103a (4)
                // .....00001009_103a (5)
                // ......goal (6)

                assertTrue(path.get(0).getVertexName().equals("FUN_00001060_pre_1060"),
                        "Incorrect path (0)");
                assertTrue(path.get(1).getVertexName().equals("00001060_1060"),
                        "Incorrect path (1)");
                assertTrue(path.get(2).getVertexName().equals("FUN_00001030_pre_1065"),
                        "Incorrect path (2)");
                assertTrue(path.get(3).getVertexName().equals("00001030_1065"),
                        "Incorrect path (3)");
                assertTrue(path.get(4).getVertexName().equals("FUN_00001000_pre_103a"),
                        "Incorrect path (4)");
                assertTrue(path.get(5).getVertexName().equals("00001000_103a"),
                        "Incorrect path (5)");
                assertTrue(path.get(6).getVertexName().equals("00001009_103a"),
                        "Incorrect path (6)");
                assertTrue(path.get(7).getVertexName().equals("goal"), "Incorrect goal");

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testMsvc32bMultiFuncSatPathVarAssignment() {

            // ****************************************************************
            // 00001000: PUSH EBP
            // 00001001: MOV EBP,ESP
            // 00001003: CMP dword ptr [EBP + 0x8],0x2b
            // 00001007: JNZ 0x00001015
            // 00001009: MOV dword ptr [0x00403000],0x43 <== END
            // 00001013: JMP 0x00001025
            // 00001015: CMP dword ptr [EBP + 0x8],0x2c
            // 00001019: JNZ 0x00001025
            // 0000101b: MOV dword ptr [0x00403000],0x2c
            // 00001025: POP EBP
            // 00001026: RET
            // CC's
            // 00001030: PUSH EBP
            // 00001031: MOV EBP,ESP
            // 00001033: MOV EAX,dword ptr [EBP + 0x8]
            // 00001036: ADD EAX,0x1
            // 00001039: PUSH EAX
            // 0000103a: CALL 0x00001000
            // 0000103f: ADD ESP,0x4
            // 00001042: MOV ECX,dword ptr [EBP + 0x8]
            // 00001045: ADD ECX,0x2
            // 00001048: PUSH ECX
            // 00001049: CALL 0x00001000
            // 0000104e: ADD ESP,0x4
            // 00001051: POP EBP
            // 00001052: RET
            // CC's
            // 00001060: PUSH EBP <== START
            // 00001061: MOV EBP,ESP
            // 00001063: PUSH 0x2a
            // 00001065: CALL 0x00001030
            // 0000106a: ADD ESP,0x4
            // 0000106d: PUSH 0x2b
            // 0000106f: CALL 0x00001030
            // 00001074: ADD ESP,0x4
            // 00001077: XOR EAX,EAX
            // 00001079: POP EBP
            // 0000107a: RET

            final Program program = testEnv.buildTestProgram("Test",
                    "55 8b ec 83 7d 08 2b 75 0c c7 05 00 30 40 00 43 00 00 00 eb 10 83"
                            + "7d 08 2c 75 0a c7 05 00 30 40 00 2c 00 00 00 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc 55 8b ec 8b 45 08 83 c0 01 50 e8 c1 ff ff ff 83 c4 04"
                            + "8b 4d 08 83 c1 02 51 e8 b2 ff ff ff 83 c4 04 5d c3 cc cc cc cc cc"
                            + "cc cc cc cc cc cc cc cc 55 8b ec 6a 2a e8 c6 ff ff ff 83 c4 04 6a"
                            + "2b e8 bc ff ff ff 83 c4 04 33 c0 5d c3",
                    Arrays.asList(new String[] {"0x1000", "0x1030", "0x1060"}),
                    ProgramBuilder._X86);

            final Address start =
                    program.getAddressFactory().getAddress("0x1060");
            final Address end =
                    program.getAddressFactory().getAddress("0x1009");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                GhiHornAnswer ans = listener.getAnswer().get(0);
                assertTrue(ans != null);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

                final List<GhiHornAnswerGraphVertex> path = ans.answerGraph.getVerticesInPreOrder();

                // The correct path is:
                //
                // 00001060_1060
                // .FUN_00001030_pre_1065 (1)
                // ..00001030_1065 (2)
                // ...FUN_00001000_pre_103a (3)
                // ....00001000_103a (4)
                // .....00001009_103a (5)
                // ......goal (6)

                synchronized (path) {

                    final String datVar = "DAT_00403000!Test";
                    final String paramVarFUN_00001030 = "param_1@FUN_00001030!Test";
                    final String paramVarFUN_00001000 = "param_1@FUN_00001000!Test";

                    for (GhiHornAnswerGraphVertex v : path) {

                        Map<HornVariable, String> vals =
                                ((GhiHornSatAttributes) v.getAttributes()).getValueMap();

                        Map<String, String> nameValMap =
                                vals.entrySet()
                                        .stream()
                                        .collect(Collectors.toMap(
                                                e -> e.getKey().getVariableName().getFullName(),
                                                Map.Entry::getValue));

                        if (v.getVertexName().equals("00001060_1060")) {

                            // 00001060_1060(Memory = N/A, DAT_00403000!Test = 0x00)

                            assertTrue(nameValMap.get(datVar).equals("0"),
                                    "Failed " + datVar + " wrong");

                        } else if (v.getVertexName().equals("FUN_00001030_pre_1065")) {

                            // FUN_00001030_pre_1065(Memory = N/A, DAT_00403000!Test = 0x00,
                            // param_1@FUN_00001030!Test = 0x2a)

                            assertTrue(nameValMap.get(datVar).equals("0"),
                                    "Failed " + datVar + " wrong");
                            assertTrue(nameValMap.get(paramVarFUN_00001030).equals("42"),
                                    "Failed " + paramVarFUN_00001030 + " wrong");

                        } else if (v.getVertexName().equals("00001030_1065")) {
                            // 00001030_1065(Memory = N/A, DAT_00403000!Test = 0x00,
                            // param_1@FUN_00001030!Test = 0x2a)

                            assertTrue(nameValMap.get(datVar).equals("0"),
                                    "Failed " + datVar + " wrong");

                            assertTrue(nameValMap.get(paramVarFUN_00001030).equals("42"),
                                    "Failed " + paramVarFUN_00001030 + " wrong");

                        } else if (v.getVertexName().equals("FUN_00001000_pre_103a")) {
                            // FUN_00001000_pre_103a(DAT_00403000!Test = 0x00, Memory = N/A,
                            // param_1@FUN_00001000!Test = 0x2b)

                            assertTrue(nameValMap.get(datVar).equals("0"),
                                    "Failed " + datVar + " wrong");

                            assertTrue(nameValMap.get(paramVarFUN_00001000).equals("43"),
                                    "Failed " + paramVarFUN_00001000 + " wrong");

                        } else if (v.getVertexName().equals("00001000_103a")) {
                            // 00001000_103a(DAT_00403000!Test = 0x00, Memory = N/A,
                            // param_1@FUN_00001000!Test = 0x2b)

                            assertTrue(nameValMap.get(datVar).equals("0"),
                                    "Failed " + datVar + " wrong");

                            assertTrue(nameValMap.get(paramVarFUN_00001000).equals("43"),
                                    "Failed " + paramVarFUN_00001000 + " wrong");

                        } else if (v.getVertexName().equals("00001009_103a")) {

                            // 00001009_103a(Memory = N/A, DAT_00403000!Test = 0x00,
                            // param_1@FUN_00001000!Test = 0x2b)

                            assertTrue(nameValMap.get(datVar).equals("0"),
                                    "Failed " + datVar + " wrong");

                            assertTrue(nameValMap.get(paramVarFUN_00001000).equals("43"),
                                    "Failed " + paramVarFUN_00001000 + " wrong");

                        }
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
                fail();
            }
        }

        @Test
        public void testGcc64bMachOMultiFuncSat() {

            // ****************************************************************
            // 00001000: PUSH RBP
            // 00001001: MOV RBP,RSP
            // 00001004: MOV dword ptr [RBP + -0x4],EDI
            // 00001007: CMP dword ptr [RBP + -0x4],0x2b
            // 0000100b: JNZ 0x00001020
            // 00001011: MOV dword ptr [0x000010f0],0x43 <== GOAL HERE
            // 0000101b: JMP 0x00001039
            // 00001020: CMP dword ptr [RBP + -0x4],0x2c
            // 00001024: JNZ 0x00001034
            // 0000102a: MOV dword ptr [0x000010f0],0x2c
            // 00001034: JMP 0x00001039
            // 00001039: POP RBP
            // 0000103a: RET
            //
            // 00001040: PUSH RBP
            // 00001041: MOV RBP,RSP
            // 00001044: SUB RSP,0x10
            // 00001048: MOV dword ptr [RBP + -0x4],EDI
            // 0000104b: MOV EAX,dword ptr [RBP + -0x4]
            // 0000104e: ADD EAX,0x1
            // 00001051: MOV EDI,EAX
            // 00001053: CALL 0x00001000
            // 00001058: MOV EAX,dword ptr [RBP + -0x4]
            // 0000105b: ADD EAX,0x2
            // 0000105e: MOV EDI,EAX
            // 00001060: CALL 0x00001000
            // 00001065: ADD RSP,0x10
            // 00001069: POP RBP
            // 0000106a: RET
            //
            // 00001070: PUSH RBP
            // 00001071: MOV RBP,RSP
            // 00001074: SUB RSP,0x10
            // 00001078: MOV dword ptr [RBP + -0x4],0x0
            // 0000107f: MOV dword ptr [RBP + -0x8],EDI
            // 00001082: MOV qword ptr [RBP + -0x10],RSI
            // 00001086: MOV EDI,0x2a
            // 0000108b: CALL 0x00001040
            // 00001090: MOV EDI,0x2b
            // 00001095: CALL 0x00001040
            // 0000109a: XOR EAX,EAX
            // 0000109c: ADD RSP,0x10
            // 000010a0: POP RBP

            final Program program = testEnv.buildTestProgram("Test",
                    "55 48 89 e5 89 7d fc 83 7d fc 2b 0f 85 0f 00 00 00 c7 05 d5 00 00 00"
                            + "43 00 00 00 e9 19 00 00 00 83 7d fc 2c 0f 85 0a 00 00 00 c7 05 bc 00"
                            + "00 00 2c 00 00 00 e9 00 00 00 00 5d c3 0f 1f 44 00 00 55 48 89 e5 48"
                            + "83 ec 10 89 7d fc 8b 45 fc 83 c0 01 89 c7 e8 a8 ff ff ff 8b 45 fc 83"
                            + "c0 02 89 c7 e8 9b ff ff ff 48 83 c4 10 5d c3 0f 1f 44 00 00 55 48 89"
                            + "e5 48 83 ec 10 c7 45 fc 00 00 00 00 89 7d f8 48 89 75 f0 bf 2a 00 00"
                            + "00 e8 b0 ff ff ff bf 2b 00 00 00 e8 a6 ff ff ff 31 c0 48 83 c4 10 5d c3 90 90",
                    Arrays.asList(new String[] {"0x1000", "0x103b", "0x1070"}),
                    ProgramBuilder._X64);

            final Address start =
                    program.getAddressFactory().getAddress("0x1070");

            final Address end =
                    program.getAddressFactory().getAddress("0x1011");

            try {

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpPathAnalyzer(start, start, end);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                GhiHornAnswer ans = listener.getAnswer().get(0);
                assertTrue(ans != null);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
    }


    @Nested
    @DisplayName("ApiAnalyzer Tests")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class ApiAnalyzerTests {

        @Test
        public void testSigBasics() {
            final String testSig =
                    "{ \"Signatures\": [ { \"Name\": \"TestSig\", \"Description\": \"TestSigDescription\", \"Sequence\": [ { \"API\": \"DllName.DLL::Func1\", \"Args\": [ \"HR1\", \"\", \"HR2\" ], \"Retn\": \"HR1\" }, { \"API\": \"DllName.DLL::Func2\", \"Args\": [ \"HR1\" ], \"Retn\": \"HR1\" } ] }, { \"Name\": \"TestSig2\", \"Description\": \"TestSigDescription2\", \"Sequence\": [ { \"API\": \"DllName.DLL::Func3\", \"Args\": [ \"\", \"HR3\" ] } ] } ] }";

            List<ApiSignature> sigTests = testEnv.loadSigs(testSig);
            assertTrue(sigTests.size() == 2);

            ApiSignature sig0 = sigTests.get(0);
            assertTrue("TestSig".equals(sig0.getName()));
            assertTrue("TestSigDescription".equals(sig0.getDescription()));

            ApiSignature sig1 = sigTests.get(1);
            assertTrue("TestSig2".equals(sig1.getName()));
            assertTrue("TestSigDescription2".equals(sig1.getDescription()));

        }

        @Test
        public void testSigArgsAndRetn() {
            final String testSig =
                    "{ \"Signatures\": [ { \"Name\": \"TestSig\", \"Description\": \"TestSigDescription\", \"Sequence\": [ { \"API\": \"DllName.DLL::Func1\", \"Args\": [ \"HR1\", \"\", \"HR2\" ], \"Retn\": \"HR1\" }, { \"API\": \"DllName.DLL::Func2\", \"Args\": [ \"HR1\" ], \"Retn\": \"HR1\" } ] }, { \"Name\": \"TestSig2\", \"Description\": \"TestSigDescription2\", \"Sequence\": [ { \"API\": \"DllName.DLL::Func3\", \"Args\": [ \"\", \"HR3\" ] } ] } ] }";

            List<ApiSignature> sigTests = testEnv.loadSigs(testSig);
            ApiFunction apiFunc1 = sigTests.get(0).getSequence().get(0);

            for (Map.Entry<Integer, String> entry : apiFunc1.getApiParameters().entrySet()) {
                Integer ord = entry.getKey();
                String arg = entry.getValue();
                switch (ord) {
                    case 0:
                        assertTrue(arg.equals("HR1"));
                        break;
                    case 1:
                        assertTrue(arg.isBlank());
                        break;

                    case 2:
                        assertTrue(arg.equals("HR2"));
                        break;
                }
            }
            assertTrue(apiFunc1.getApiRetnValue().equals("HR1"));
        }

        @Test
        public void testApiAnalyzerSingleFunction() {

            final String sig =
                    "{\"Signatures\": [{\"Name\": \"File Open/Close\",\"Description\": \"Open and close a file\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateFileA\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
            ApiSignature testSig = testEnv.loadSigs(sig).get(0);

            try {
                final Program program =
                        testEnv.importTestProgram("msvc32b-fileopen-single.exe");

                final Address entry =
                        program.getAddressFactory().getAddress("0x401000");

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();

                assertTrue(ansList != null);
                assertTrue(ansList.size() == 1);

                GhiHornAnswer ans = ansList.get(0);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }


        /**
         * 
         */
        @Test
        public void testApiAnalyzerSingleFuncStraighLinePath() {

            try {
                // Single function API sequence
                final Program program =
                        testEnv.importTestProgram("msvc32b-fileopen-single.exe");

                final String sig =
                        "{\"Signatures\": [{\"Name\": \"File Open/Close\",\"Description\": \"Open and close a file\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateFileA\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
                ApiSignature testSig = testEnv.loadSigs(sig).get(0);

                final Address entry =
                        program.getAddressFactory().getAddress("0x401000");

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();

                assertTrue(ansList != null);
                assertTrue(ansList.size() == 1);

                // Fetch the sat answer and check the path
                GhiHornAnswer ans = ansList.get(0);

                // The correct path is:
                //
                // start_00401000_401000(SEQUENCE = 0x00)
                // 00401000_401000(hObject@FUN_00401000 = 0x00, Memory = N/A, SEQUENCE = 0x00)
                // KERNEL32.DLL::CREATEFILEA_pre_40101b(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x00)
                // KERNEL32.DLL::CREATEFILEA_post_40101b(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x01)
                // 00401021_401000(hObject@FUN_00401000 = 0x00, Memory = N/A, SEQUENCE = 0x01)
                // KERNEL32.DLL::CLOSEHANDLE_pre_401028(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x01)
                // KERNEL32.DLL::CLOSEHANDLE_post_401028(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x02)
                // goal()

                final List<GhiHornAnswerGraphVertex> path = ans.answerGraph.getVerticesInPreOrder();
                assertTrue(path.get(0).getVertexName().equals("start"),
                        "Incorrect start");

                assertTrue(path.get(1).getVertexName().equals("FUN_00401000_pre_401000"),
                        "Incorrect path (1)");
                assertTrue(path.get(2).getVertexName().equals("00401000_401000"),
                        "Incorrect path (2)");
                assertTrue(
                        path.get(3).getVertexName().equals("KERNEL32.DLL::CREATEFILEA_pre_40101b"),
                        "Incorrect path (2)");
                assertTrue(
                        path.get(4).getVertexName().equals("KERNEL32.DLL::CREATEFILEA_post_40101b"),
                        "Incorrect path (3)");
                assertTrue(path.get(5).getVertexName().equals("00401021_401000"),
                        "Incorrect path (4)");
                assertTrue(
                        path.get(6).getVertexName().equals("KERNEL32.DLL::CLOSEHANDLE_pre_401028"),
                        "Incorrect path (5)");
                assertTrue(
                        path.get(7).getVertexName().equals("KERNEL32.DLL::CLOSEHANDLE_post_401028"),
                        "Incorrect path (5)");
                assertTrue(path.get(8).getVertexName().equals("goal"), "Incorrect goal");

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        public void testApiAnalyzerMultiFuncCall() {

            try {
                // Single function API sequence
                final Program program =
                        testEnv.importTestProgram("msvc32b-fileopen-single.exe");

                final String sig =
                        "{\"Signatures\": [{\"Name\": \"File Open/Close\",\"Description\": \"Open and close a file\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateFileA\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
                ApiSignature testSig = testEnv.loadSigs(sig).get(0);


                final Address entry =
                        program.getAddressFactory().getAddress("0x401000");
                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                final HornProgram hornProgram = hornifier.hornify(program, TaskMonitor.DUMMY);
                hornifier.evaluate(hornProgram, TaskMonitor.DUMMY);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();

                assertTrue(ansList != null);
                assertTrue(ansList.size() == 2);

                // Fetch the sat answer and check the path.
                GhiHornAnswer ans = ansList.get(0);
                if (ans.status == GhiHornFixedpointStatus.Unsatisfiable) {
                    ans = ansList.get(1);
                }

                // The correct path is:
                //
                // start_00401000_401000(SEQUENCE = 0x00)
                // 00401000_401000(hObject@FUN_00401000 = 0x00, Memory = N/A, SEQUENCE = 0x00)
                // KERNEL32.DLL::CREATEFILEA_pre_40101b(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x00)
                // KERNEL32.DLL::CREATEFILEA_post_40101b(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x01)
                // 00401021_401000(hObject@FUN_00401000 = 0x00, Memory = N/A, SEQUENCE = 0x01)
                // KERNEL32.DLL::CLOSEHANDLE_pre_401028(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x01)
                // KERNEL32.DLL::CLOSEHANDLE_post_401028(hObject@FUN_00401000 = 0x00, Memory =
                // N/A, SEQUENCE = 0x02)
                // goal()

                final List<GhiHornAnswerGraphVertex> path = ans.answerGraph.getVerticesInPreOrder();
                assertTrue(path.get(0).getVertexName().equals("start_00401000_401000"),
                        "Incorrect start");
                assertTrue(path.get(1).getVertexName().equals("00401000_401000"),
                        "Incorrect path (1)");
                assertTrue(
                        path.get(2).getVertexName().equals("KERNEL32.DLL::CREATEFILEA_pre_40101b"),
                        "Incorrect path (2)");
                assertTrue(
                        path.get(3).getVertexName().equals("KERNEL32.DLL::CREATEFILEA_post_40101b"),
                        "Incorrect path (3)");
                assertTrue(path.get(4).getVertexName().equals("00401021_401000"),
                        "Incorrect path (4)");
                assertTrue(
                        path.get(5).getVertexName().equals("KERNEL32.DLL::CLOSEHANDLE_pre_401028"),
                        "Incorrect path (5)");
                assertTrue(
                        path.get(6).getVertexName().equals("KERNEL32.DLL::CLOSEHANDLE_post_401028"),
                        "Incorrect path (5)");
                assertTrue(path.get(7).getVertexName().equals("goal"), "Incorrect goal");

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testApiAnalyzerMultiFunctionSeqPath() {

            try {
                // A test with an API sequence split over two functions
                final Program program =
                        testEnv.importTestProgram("msvc32b-fileopen-inter.exe");

                final String sig =
                        "{\"Signatures\": [{\"Name\": \"File Open/Close\",\"Description\": \"Open and close a file\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateFileA\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
                ApiSignature testSig = testEnv.loadSigs(sig).get(0);

                Address entry = program.getSymbolTable()
                        .getExternalEntryPointIterator()
                        .next();

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();

                assertTrue(ansList != null);

                // Fetch the sat answer and check the path
                GhiHornAnswer ans = ansList.get(0);
                assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        /**
         * Test that the starting point for the test program are properly found
         */
        @Test
        public void testApiAnalyzerMultiApiCallStarts() {

            try {
                // A test with an API sequence split over two functions
                final Program program =
                        testEnv.importTestProgram("msvc32b-call-apis-twice.exe");
                final String sig =
                        "{\"Signatures\": [{\"Name\": \"File Open/Close\",\"Description\": \"Open and close a file\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateFileA\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
                ApiSignature testSig = testEnv.loadSigs(sig).get(0);

                Address entry = program.getSymbolTable()
                        .getExternalEntryPointIterator()
                        .next();

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();

                assertTrue(ansList != null);

                // Fetch the sat answer and check the path
                assertTrue(ansList.size() == 4);

                int found2aStart = 0;
                int found49Start = 0;

                for (GhiHornAnswer ans : ansList) {
                    ApiAnalyzerArgument coord = (ApiAnalyzerArgument) ans.arguments;
                    for (GhiHornAnswerGraphVertex v : ans.answerGraph.getVerticesInPreOrder()) {
                        Address vtxAddr = v.getAttributes().getAddress();
                        if (vtxAddr.equals(coord.getEntryAsAddress())) {
                            Msg.info(this, "Entry: " + vtxAddr);
                        }
                        if (vtxAddr.equals(coord.getStartAsAddress())) {
                            Msg.info(this, "Start: " + vtxAddr);
                        }
                        if (vtxAddr.equals(coord.getGoalAsAddress())) {
                            Msg.info(this, "Goal: " + vtxAddr);
                        }
                    }

                    if (coord.getStartAsAddress().toString().equals("0040102a")) {
                        found2aStart++;
                    }
                    if (coord.getStartAsAddress().toString().equals("00401049")) {
                        found49Start++;
                    }
                }
                assertTrue(found2aStart == 2, "Failed to start at address 0x40102a");
                assertTrue(found49Start == 2, "Failed to start at address 0x401049");

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testApiAnalyzerParamsUnsat() {

            // This is a stripped down instance of kernel32.dll that has 9 global variables
            try {
                final List<HighFunction> importFuncList = testEnv.decompileTestProgram(
                        "KERNEL32.DLL",
                        // undefined4 _CreateFileA@28(void) { return 0x42; }
                        "55 8b ec 83 7d 08 00 74 25 83 7d 0c 00 74 1f 83 7d 10 00 74 19 83 7d 14 00 74 13 83 7d 18 00 74 0d 83 7d 1c 00 74 07 83 7d 20 ff 74 01 90 b8 42 00 00 00 5d c2 1c 00 cc cc cc cc cc cc cc cc cc"
                                +
                                // bool _CloseHandle@4(int param_1) { return param_1 == 0x42; }
                                "55 8b ec 83 7d 08 42 75 07 b8 01 00 00 00 eb 02 33 c0 5d c2 04 00 cc cc cc cc cc cc cc cc cc cc"
                                +
                                // undefined4 entry(void) { return 1; }
                                "55 8b ec b8 01 00 00 00 5d c2 0c 00",
                        Arrays.asList(new String[] {"0x1000", // CreateFileA
                                "0x1040", // CloseHandle
                                "0x1060" // OEP
                        }),
                        ProgramBuilder._X86);
                Program p = importFuncList.get(0).getFunction().getProgram();
                tx(p, () -> importFuncList.get(0).getFunction().setName("CreateFileA",
                        SourceType.USER_DEFINED));
                tx(p, () -> importFuncList.get(1).getFunction().setName("CloseHandle",
                        SourceType.USER_DEFINED));

                DummyApiDatabase apiDb = new DummyApiDatabase();
                apiDb.installPreloadedLibrary("KERNEL32.DLL", importFuncList);

                // A test with an API sequence split over two functions
                final Program program =
                        testEnv.importTestProgram("msvc32b-call-apis-twice-nested-param-unsat.exe");

                // DAT_00403000 = 0x43;
                // HANDLE pvVar1 =
                // CreateFileA("name",0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,1,0x80,(HANDLE)0x0);
                // if (pvVar1 != (HANDLE)0xffffffff)
                // CloseHandle(DAT_00403000); <- kernel32.dll returns 0x42, passing 0x43 is unsat
                // }

                final String sig =
                        "{\"Signatures\": [{\"Name\": \"File Open/Close\",\"Description\": \"Open and close a file\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateFileA\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
                ApiSignature testSig = testEnv.loadSigs(sig).get(0);

                Address entry = program.getSymbolTable()
                        .getExternalEntryPointIterator()
                        .next();

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig, apiDb);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();
                GhiHornAnswer ans = ansList.get(0);

                // This is unsat because the API parameters do not align
                assertTrue(ans.status == GhiHornFixedpointStatus.Unsatisfiable);

            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }

        @Test
        public void testApiAnalyzerMultiApiCallParamsComplex() {

            // This is a stripped down instance of kernel32.dll that has 9 global variables
            try {
                final List<HighFunction> importFuncList =
                        testEnv.importAndDecompileProgram(
                                "inc-kernel32.dll");

                Program p = importFuncList.get(0).getFunction().getProgram();
                tx(p, () -> importFuncList.get(0).getFunction().setName("CreateFileA",
                        SourceType.USER_DEFINED));
                tx(p, () -> importFuncList.get(1).getFunction().setName("CloseHandle",
                        SourceType.USER_DEFINED));

                DummyApiDatabase apiDb = new DummyApiDatabase();
                apiDb.installPreloadedLibrary("KERNEL32.DLL", importFuncList);

                // A test with an API sequence split over two functions
                final Program program =
                        testEnv.importTestProgram(
                                "msvc32b-call-apis-twice-nested.exe");

                final String sig =
                        "{\"Signatures\": [{\"Name\": \"File Open/Close\",\"Description\": \"Open and close a file\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateFileA\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
                ApiSignature testSig = testEnv.loadSigs(sig).get(0);

                Address entry = program.getSymbolTable()
                        .getExternalEntryPointIterator()
                        .next();

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig, apiDb);

                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);

                int i = 0;
                while (i < 10 && listener.isDone() == false) {
                    Thread.sleep(100);
                    ++i;
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();

                // There are 4 answers: 2 sat and 2 unsat
                assertTrue(ansList.size() == 4);

                for (GhiHornAnswer ans : ansList) {
                    ApiAnalyzerArgument coord = (ApiAnalyzerArgument) ans.arguments;
                    if (coord.getStartAsAddress().toString().equals("00401049")
                            && coord.getGoalAsAddress().toString().equals("0040106c")) {
                        assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);
                    } else if (coord.getStartAsAddress().toString().equals("0040102a")
                            && coord.getGoalAsAddress().toString().equals("0040105c")) {
                        assertTrue(ans.status == GhiHornFixedpointStatus.Satisfiable);
                    } else if (coord.getStartAsAddress().toString().equals("0040102a")
                            && coord.getGoalAsAddress().toString().equals("0040106c")) {
                        assertTrue(ans.status == GhiHornFixedpointStatus.Unsatisfiable);
                    } else if (coord.getStartAsAddress().toString().equals("00401049")
                            && coord.getGoalAsAddress().toString().equals("0040105c")) {
                        assertTrue(ans.status == GhiHornFixedpointStatus.Unsatisfiable);
                    }

                    StringBuilder sb = new StringBuilder("===\n").append(coord).append("\n");
                    GhiHornDisplaySettings displaySettings = (new GhiHornDisplaySettingBuilder())
                            .showGlobalVariables(true)
                            .showLocalVariables(true)
                            .hideExternalFuncs(false)
                            .generateText()
                            .build();
                    sb.append(
                            ans.answerGraph.format(GhiHornOutputFormatter.create(displaySettings)));
                    sb.append("\n===");
                    Msg.info(this, sb);
                }
            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }


        @Test
        @Disabled
        public void testTaskList() {

            try {
                // A test with an API sequence split over two functions
                final Program program =
                        testEnv.importTestProgram("tasklist.exe");
                final String sig =
                        "{\"Signatures\": [{\"Name\": \"TaskList\",\"Description\": \"TaskList\",\"Sequence\": [{\"API\": \"Kernel32.DLL::CreateToolhelp32Snapshot\",\"Retn\": \"H\"},{\"API\": \"Kernel32.DLL::Process32First\",\"Args\": [\"H\"]},{\"API\": \"Kernel32.DLL::Process32Next\",\"Args\": [\"H\"]},{\"API\": \"Kernel32.DLL::CloseHandle\",\"Args\": [\"H\"]}]}]}";
                ApiSignature testSig = testEnv.loadSigs(sig).get(0);

                Address entry = program.getSymbolTable()
                        .getExternalEntryPointIterator()
                        .next();

                Pair<GhiHornEventListener, GhiHornifier> toolPair =
                        testEnv.setUpApiAnalyzer(entry, testSig);
                GhiHornEventListener listener = toolPair.first;
                GhiHornifier hornifier = toolPair.second;

                GhiHornCommand cmd = new GhiHornCommand("test", hornifier);
                cmd.addCommandListener(listener);
                cmd.applyTo(program);
                
                while (!listener.isDone()) {
                    Thread.sleep(100);
                }
                List<GhiHornAnswer> ansList = listener.getAnswer();

                assertTrue(ansList.size() >0); 


            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
    }
}
