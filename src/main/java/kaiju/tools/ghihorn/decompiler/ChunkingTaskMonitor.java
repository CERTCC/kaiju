package kaiju.tools.ghihorn.decompiler;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * A class that exists because we are doing something that the ConcurrentQ was not designed
 * for--chunking. We do not want out monitor being reset every time we start a new chunk. So, we
 * wrap a real monitor, overriding the behavior such that initialize() has no effect when it is
 * called by the queue.
 */
public class ChunkingTaskMonitor extends TaskMonitorAdapter {
    private TaskMonitor monitor;

    public ChunkingTaskMonitor(TaskMonitor monitor) {
        this.monitor = monitor;
    }

    public void doInitialize(long value) {
        // this lets us initialize when we want to
        monitor.initialize(value);
    }

    @Override
    public void setProgress(long value) {
        monitor.setProgress(value);
    }

    @Override
    public void checkCancelled() throws CancelledException {
        monitor.checkCancelled();
    }

    @Override
    public void setMessage(String message) {
        monitor.setMessage(message);
    }

    @Override
    public synchronized void addCancelledListener(CancelledListener listener) {
        monitor.addCancelledListener(listener);
    }

    @Override
    public synchronized void removeCancelledListener(CancelledListener listener) {
        monitor.removeCancelledListener(listener);
    }
}
