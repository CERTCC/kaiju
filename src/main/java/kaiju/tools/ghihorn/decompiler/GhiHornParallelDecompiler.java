package kaiju.tools.ghihorn.decompiler;

import kaiju.common.KaijuGhidraCompat;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import generic.cache.CachingPool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.ChunkingParallelDecompiler;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** 
 * A parallel decompiler that uses Ghidra's thread pool services
 */
public class GhiHornParallelDecompiler implements GhiHornDecompiler {
    private ServiceProvider serviceProvider;

    public GhiHornParallelDecompiler(ServiceProvider sp) {
        this.serviceProvider = sp;
    }

    /**
     * Create a parallel decompiler
     * 
     * @param program the program to decompile
     * @param monitor task monitor
     * @return
     * @throws CancelledException
     * @throws Exception
     */
    @Override
    public List<HighFunction> decompileProgram(Program program, TaskMonitor monitor)
        throws CancelledException, Exception {    

            final Set<Function> functions = new HashSet<>();

            program.getFunctionManager().getFunctions(true).forEach(functions::add);
    
            List<HighFunction> highFuncList = new ArrayList<>();
    
            CachingPool<DecompInterface> decompilerPool =
                    new CachingPool<>(new DecompilerFactory(program, serviceProvider));
    
            ParallelDecompilerCallback callback =
                    new ParallelDecompilerCallback(decompilerPool);
    
            ChunkingTaskMonitor chunkingMonitor = new ChunkingTaskMonitor(monitor);
            ChunkingParallelDecompiler<HighFunction> parallelDecompiler =
                    ParallelDecompiler.createChunkingParallelDecompiler(callback, chunkingMonitor);
    
            chunkingMonitor.doInitialize(program.getFunctionManager().getFunctionCount());
    
            List<Function> functionChunks = new ArrayList<>();
            Iterator<Function> iterator = functions.iterator();
            for (int i = 0; iterator.hasNext(); i++) {
    
                // Save results every so many items so that we don't blow out memory
    
                if (i % 10000 == 0) {
                    highFuncList.addAll(parallelDecompiler.decompileFunctions(functionChunks));
                    functionChunks.clear();
                }
                functionChunks.add(iterator.next());
            }
    
            // handle any remaining functions
    
            highFuncList.addAll(parallelDecompiler.decompileFunctions(functionChunks));
            decompilerPool.dispose();
    
            return highFuncList;
        }

    public HighFunction decompileFunction(Function function, TaskMonitor monitor) throws Exception {
                
        Program program = function.getProgram();
                
        DecompInterface decompiler = new DecompInterface();

        // call it to get results
        if (!decompiler.openProgram(program)) {

            return null;
        }

        DecompileOptions options;
        options = new DecompileOptions();

        ToolOptions opt = KaijuGhidraCompat.getToolOptions(this.serviceProvider, "Decompiler");
        options.grabFromToolAndProgram(null, opt, program);

        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        DecompileResults res = decompiler.decompileFunction(function,
                decompiler.getOptions().getDefaultTimeout(), monitor);

        return res.getHighFunction();
    }

}
