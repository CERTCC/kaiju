package kaiju.tools.ghihorn.frg;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidra.app.services.BlockModelService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * Builds a Function Reachability Graph. This code is extracted from the Ghidra Reachability Plugin
 * 
 * @see ghidra.app.plugin.core.reachability
 */
public class FrgBuilder {
    private final ServiceProvider serviceProvider;
    private Function fromFunction;
    private Function toFunction;
    private Program program;

	/**
	 * 
	 * @param sp
	 */
	public FrgBuilder(ServiceProvider sp) {
		this.serviceProvider = sp;
		this.fromFunction = null;
		this.toFunction = null;
	}

	/**
	 * 
	 * @param monitor
	 * @param from
	 * @param to
	 * @return
	 * @throws CancelledException
	 */
	public Accumulator<FrgResult> findFunctionCallPaths(TaskMonitor monitor, final Function from,
			final Function to) throws CancelledException {

		this.fromFunction = from;
		this.toFunction = to;

		monitor.setMessage("Creating reachability graph...");

		Map<Address, FrgVertex> instanceMap = new HashMap<>();
		FrgVertex fromVtx = new FrgVertex(this.fromFunction.getEntryPoint());
		FrgVertex toVtx = new FrgVertex(this.toFunction.getEntryPoint());

		// there is no path to yourself
		if (fromVtx.equals(toVtx)) {
			return null;
		}
		instanceMap.put(fromFunction.getEntryPoint(), fromVtx);
		instanceMap.put(toFunction.getEntryPoint(), toVtx);

		GDirectedGraph<FrgVertex, FrgEdge> graph = createCallGraph(instanceMap, monitor);

		monitor.setMessage("Finding paths...");


		// ListAccumulator became thread safe in Ghidra 12.2.
#if GHIDRA_12_2 == "true"
		ListAccumulator<FrgResult> pathAccumulator = new ListAccumulator<>();
#else
		ListAccumulator<FrgResult> pathAccumulator =
			new ListAccumulator<>(Collections.synchronizedList(new ArrayList<>()));
#endif

		GraphAlgorithms.findPaths(graph, fromVtx, toVtx,
				new PassThroughAccumulator(pathAccumulator), monitor);

		if (pathAccumulator.size() == 0) {
			Set<FrgVertex> fromAncestors = GraphAlgorithms.getAncestors(graph, new ArrayList<>() {
				{
					add(fromVtx);
				}
			});
			if (fromAncestors.contains(toVtx)) {

				// if from is an ancestor of to, that can be because to calls
				// from early on in the method

				Msg.info(null,
						toFunction.getName() + " is an ancestor of " + fromFunction.getName());
				GraphAlgorithms.findPaths(graph, toVtx, fromVtx,
						new PassThroughAccumulator(pathAccumulator), monitor);
			}
		}

		return pathAccumulator;
	}

	public void setFunctions(Function from, Function to) {
		this.fromFunction = from;
		this.toFunction = to;
        this.program = fromFunction.getProgram();
	}

	/**
	 * 
	 * @param instanceMap
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 */
	private GDirectedGraph<FrgVertex, FrgEdge> createCallGraph(Map<Address, FrgVertex> instanceMap,
			TaskMonitor monitor) throws CancelledException {

		GDirectedGraph<FrgVertex, FrgEdge> graph = GraphFactory.createDirectedGraph();

		CodeBlockIterator codeBlocks = getCallGraphBlocks(monitor);

		while (codeBlocks.hasNext()) {
			monitor.checkCancelled();

			CodeBlock block = codeBlocks.next();
			monitor.setMessage("Creating callgraph - block " + block.getMinAddress());

			FrgVertex fromVertex = instanceMap.get(block.getFirstStartAddress());

			if (fromVertex == null) {
				fromVertex = new FrgVertex(block.getFirstStartAddress());
				instanceMap.put(block.getFirstStartAddress(), fromVertex);
				graph.addVertex(fromVertex);
			}

			// destinations section
			addEdgesForDestinations(graph, fromVertex, block, instanceMap, monitor);
		}
		return graph;
	}

	/**
	 * 
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 */
	private CodeBlockIterator getCallGraphBlocks(TaskMonitor monitor) throws CancelledException {
		BlockModelService blockModelService = serviceProvider.getService(BlockModelService.class);

		CodeBlockModel model;
        
		try {
			model = blockModelService
					.getNewModelByName(BlockModelService.ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME, program);
		} catch (NotFoundException e) {
			Msg.error(this, "Code block model not found: "
					+ BlockModelService.ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME);
			model = blockModelService.getActiveSubroutineModel(program);
		}

		return model.getCodeBlocks(monitor);
	}

	/**
	 * 
	 * @param graph
	 * @param fromVertex
	 * @param sourceBlock
	 * @param vertexMap
	 * @param monitor
	 * @throws CancelledException
	 */
	private void addEdgesForDestinations(GDirectedGraph<FrgVertex, FrgEdge> graph,
			FrgVertex fromVertex, CodeBlock sourceBlock, Map<Address, FrgVertex> vertexMap,
			TaskMonitor monitor) throws CancelledException {

		CodeBlockReferenceIterator iterator = sourceBlock.getDestinations(monitor);
		while (iterator.hasNext()) {
			monitor.checkCancelled();

			CodeBlockReference destination = iterator.next();
			CodeBlock targetBlock = getDestinationBlock(destination, monitor);
			if (targetBlock == null) {
				continue; // no block found
			}

			FrgVertex targetVertex = vertexMap.get(targetBlock.getFirstStartAddress());
			if (targetVertex == null) {
				targetVertex = new FrgVertex(targetBlock.getFirstStartAddress());
				vertexMap.put(targetBlock.getFirstStartAddress(), targetVertex);
			}

			targetVertex.addReference(fromVertex, destination);

			graph.addVertex(targetVertex);
			graph.addEdge(new FrgEdge(fromVertex, targetVertex));
		}
	}

	/**
	 * 
	 * @param destination
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 */
	private CodeBlock getDestinationBlock(CodeBlockReference destination, TaskMonitor monitor)
			throws CancelledException {

		Address targetAddress = destination.getDestinationAddress();
		BlockModelService blockModelService = serviceProvider.getService(BlockModelService.class);
		CodeBlockModel codeBlockModel = blockModelService.getActiveSubroutineModel(program);
		CodeBlock targetBlock = codeBlockModel.getFirstCodeBlockContaining(targetAddress, monitor);
		if (targetBlock == null) {
			return null; // no code found for call; external?
		}

		return targetBlock;
	}

	/**
	 * 
	 */
	private class PassThroughAccumulator implements Accumulator<List<FrgVertex>> {

		private ListAccumulator<FrgResult> accumulator;

		PassThroughAccumulator(ListAccumulator<FrgResult> accumulator) {
			this.accumulator = accumulator;
		}

		public Iterator<List<FrgVertex>> iterator() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void add(List<FrgVertex> t) {
			accumulator.add(new FrgResult(fromFunction, toFunction, t));
		}

		@Override
		public void addAll(Collection<List<FrgVertex>> collection) {
			for (List<FrgVertex> list : collection) {
				accumulator.add(new FrgResult(fromFunction, toFunction, list));
			}
		}

		public boolean contains(List<FrgVertex> t) {
			throw new UnsupportedOperationException();
		}

		public Collection<List<FrgVertex>> get() {
			throw new UnsupportedOperationException();
		}

		// Required by Accumulator in Ghidra 12.2; harmless on older versions.
		public int getProgress() {
			return accumulator.size();
		}

		public int size() {
			return accumulator.size();
		}

	}
}
