/***
 * CERT Kaiju
 * Copyright 2021 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 * INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY
 * MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
 * INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
 * MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
 * CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
 * TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Released under a BSD (SEI)-style license, please see LICENSE.md or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.
 * Please see Copyright notice for non-US Government use and distribution.
 *
 * Carnegie Mellon (R) and CERT (R) are registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.
 *
 * This Software includes and/or makes use of the following Third-Party Software subject to its own license:
 * 1. OpenJDK (http://openjdk.java.net/legal/gplv2+ce.html) Copyright 2021 Oracle.
 * 2. Ghidra (https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE) Copyright 2021 National Security Administration.
 * 3. GSON (https://github.com/google/gson/blob/master/LICENSE) Copyright 2020 Google.
 * 4. JUnit (https://github.com/junit-team/junit5/blob/main/LICENSE.md) Copyright 2020 JUnit Team.
 * 5. Gradle (https://github.com/gradle/gradle/blob/master/LICENSE) Copyright 2021 Gradle Inc.
 * 6. markdown-gradle-plugin (https://github.com/kordamp/markdown-gradle-plugin/blob/master/LICENSE.txt) Copyright 2020 Andres Almiray.
 * 7. Z3 (https://github.com/Z3Prover/z3/blob/master/LICENSE.txt) Copyright 2021 Microsoft Corporation.
 * 8. jopt-simple (https://github.com/jopt-simple/jopt-simple/blob/master/LICENSE.txt) Copyright 2021 Paul R. Holser, Jr.
 *
 * DM21-0792
 */
package kaiju.tools.fnhashclassic;

import java.awt.Component;
import java.awt.Container;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.text.JTextComponent;

import docking.DockingWindowManager;
import docking.widgets.table.GTableColumnModel;
import docking.widgets.table.RowObjectFilterModel;
import docking.widgets.table.TableModelWrapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.Msg;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import kaiju.hashing.FnHashSaveable;
import kaiju.util.ByteArrayList;
import kaiju.util.HexUtils;

// based on docking.widgets.table.GTableToCSV
// WARNING: We're actually expecting a GhidraTable here,
// should we change the class name?
public final class GTableToYARA {

    // TODO: is it easy to add yara signatures in following format?
        /*
        rule Func_md5_[MD5]_[ADDR]
        {
        strings:
            // File [FILENAME] @ [ADDR] ([DATE])
            // string $md5_[MD5]_[ADDR] contains [B] bytes and [I] instructions
            $md5_[MD5]_[ADDR] = { [BYTES] }
        condition:
            all of them
        }   
        */

    final static String TITLE = "Export to YARA";

    public final static void writeYARA(File file, GhidraTable table) {
        ConvertTask task = new ConvertTask(file, table, table.getModel());
        new TaskLauncher(task, table, 0);
    }

    public final static void writeYARAUsingColunns(File file, GhidraTable table,
            List<Integer> selectedColumns) {
        ConvertTask task = new ConvertTask(file, table, table.getModel(), selectedColumns);
        new TaskLauncher(task, table, 0);
    }

    private final static void writeYARA(File file, GhidraTable table, GTableColumnModel columnModel,
            TableModel model, List<Integer> columns, TaskMonitor monitor) throws IOException {

        List<TableColumn> tableColumns = null;
        if (columns.isEmpty()) {
            tableColumns = getVisibleColumnsInOrder(table, monitor);
        }
        else {
            tableColumns = getTableColumnsByIndex(table, columns);
        }

        PrintWriter writer = new PrintWriter(file);
        try {
            //writeColumnNames(writer, tableColumns, model, monitor);
            //writeNewLine(writer);
            writeModel(writer, table, tableColumns, model, monitor);
        }
        finally {
            writer.close();
        }
    }

    private static List<TableColumn> getVisibleColumnsInOrder(JTable table, TaskMonitor monitor) {

        TableColumnModel columnModel = table.getColumnModel();
        List<TableColumn> columns = new ArrayList<TableColumn>();
        for (int columnIndex = 0; columnIndex < table.getColumnCount(); ++columnIndex) {
            if (monitor.isCancelled()) {
                break;
            }
            TableColumn column = columnModel.getColumn(columnIndex);
            columns.add(column);
        }
        return columns;
    }

    private static List<TableColumn> getTableColumnsByIndex(JTable table,
            List<Integer> columnIndices) {

        TableColumnModel columnModel = table.getColumnModel();
        List<TableColumn> columns = new ArrayList<TableColumn>();
        for (Integer index : columnIndices) {
            TableColumn column = columnModel.getColumn(index);
            columns.add(column);
        }
        return columns;
    }

    private static void writeModel(PrintWriter writer, final GhidraTable table,
            List<TableColumn> tableColumns, final TableModel model, TaskMonitor monitor) {

        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) {
            // if we are filtered, then this will only get the filtered data
            writeAllModelData(writer, table, model, monitor);
            return;
        }

        monitor.setMessage("Writing model to YARA...");
        monitor.initialize(selectedRows.length);

        // WARNING: if table model ever updates, update this to use new enums
        TableColumnModel columnModel = table.getColumnModel();
        int columnCount = columnModel.getColumnCount();
        for (int i = 0; i < selectedRows.length; ++i) {
            if (monitor.isCancelled()) {
                break;
            }

            monitor.setProgress(i);

            int row = getModelRow(selectedRows[i], model);
            row = selectedRows[i];
            
            Address row_addr = ((AddressBasedTableModel) model).getAddress(row);
            
            Program current_program = table.getProgram();
            PropertyMapManager man = current_program.getUsrPropertyManager();
            ObjectPropertyMap fnhashmap = man.getObjectPropertyMap("__CERT_Kaiju_FnHash");
            
            FnHashSaveable prop = null;
            Class<?> c = null;
            try {
                c = Class.forName("ghidra.program.model.util.ObjectPropertyMap");
            } catch (ClassNotFoundException e) {
                //TODO
                return;
            }

            try
            {
                // the get() function was introduced in Ghidra 10.2
                c.getDeclaredMethod("get");
                try {
                    prop = (FnHashSaveable) c.getDeclaredMethod("get").invoke(row_addr);
                } catch (Exception e) {
                    //TODO
                    return;
                }
            } catch(NoSuchMethodException e) {
                // before Ghidra 10.2, it was getObject()
                try {
                    prop = (FnHashSaveable) c.getDeclaredMethod("getObject").invoke(row_addr);
                } catch (Exception e2) {
                    //TODO
                    return;
                }
            }
            //FnHashSaveable prop = (FnHashSaveable) fnhashmap.getObject(row_addr);
            
            String filename_value = current_program.getExecutablePath();
            
            String md5_value = current_program.getExecutableMD5();
            
            FnUtils fnu = null;
            try {
                fnu = new FnUtils(current_program.getFunctionManager().getFunctionAt(row_addr), current_program, monitor);
            } catch (Exception e) {
                // TODO: can we do something better here?
                return;
            }
            List<byte[]> fnbytes_list = fnu.getPICBytesList();
            List<byte[]> fnmask_list = fnu.getPICMask();
            ByteArrayList arrayOfBytes = new ByteArrayList();
            ByteArrayList arrayOfMasks = new ByteArrayList();
            for (int j = 0; j < fnbytes_list.size(); ++j) {
                arrayOfBytes.add(fnbytes_list.get(j));
                arrayOfMasks.add(fnmask_list.get(j));
            }
            // the HexUtils.byteArrayToHexString function handles the YARA generation
            String bytes_value = HexUtils.byteArrayToHexString(arrayOfBytes.toArray(), " ", arrayOfMasks.toArray());
            
            String addr_value = row_addr.toString();
            
            String pichash_value = prop.getPICHash();
            
            String numbytes_value = prop.getNumBytes().toString();
            
            String numinsns_value = prop.getNumInstructions().toString();
            
            // write values in YARA format
            writeYaraSignature(writer, filename_value, md5_value, bytes_value, addr_value, pichash_value, numbytes_value, numinsns_value, monitor);
            
            // two new lines to give a visual break
            writeNewLine(writer);
            writeNewLine(writer);
        }
    }

    private static String getColumnValue(final JTable table, final TableModel model, final int row,
            final int column) {
        final String[] result = new String[1];
        try {
            SwingUtilities.invokeAndWait(() -> result[0] = getTableCellValue(table, model, row, column));
        }
        catch (InterruptedException e) {
            return null;
        }
        catch (InvocationTargetException e) {
            return null;
        }

        return result[0];
    }

    /**
     * Attempts to get the text value for the cell so that the data will match what the user sees. 
     */
    private static String getTableCellValue(JTable table, TableModel model, int row, int column) {
        TableCellRenderer renderer = table.getCellRenderer(row, column);
        TableColumnModel columnModel = table.getColumnModel();
        TableColumn tableColumn = columnModel.getColumn(column);
        int modelIndex = tableColumn.getModelIndex();
        Object value = model.getValueAt(row, modelIndex);
        
        Component component =
            renderer.getTableCellRendererComponent(table, value, false, false, row, column);

        if (component instanceof JLabel) {
            JLabel label = (JLabel) component;
            return getTextForLabel(label);
        }

        String text = lookForTextInsideOfComponent(component);
        if (text != null) {
            return text;
        }

        return value == null ? "" : value.toString();
    }

    private static String getTextForLabel(JLabel label) {
        String text = label.getText();
        if (text != null) {
            return text;
        }

        Icon icon = label.getIcon();
        if (icon == null) {
            return null;
        }
        if (icon instanceof ImageIcon) {
            return ((ImageIcon) icon).getDescription();
        }

        return null;
    }

    private static String lookForTextInsideOfComponent(Component component) {
        if (!(component instanceof Container)) {
            return null;
        }
        Container container = (Container) component;
        Component[] components = container.getComponents();
        for (Component child : components) {
            if (child instanceof JLabel) {
                // check for a label with text (one without text could be used for an icon)
                JLabel label = (JLabel) child;
                String text = label.getText();
                if (text != null) {
                    return text;
                }
            }
            else if (child instanceof JTextComponent) {
                // surely this is for displaying text
                JTextComponent textComponent = (JTextComponent) child;
                return textComponent.getText();
            }
        }

        return null;
    }

    private static int getModelRow(int viewRow, TableModel model) {
        if (model instanceof RowObjectFilterModel<?>) {
            RowObjectFilterModel<?> threadedModel = (RowObjectFilterModel<?>) model;
            return threadedModel.getModelRow(viewRow);
        }
        else if (model instanceof TableModelWrapper) {
            TableModelWrapper<?> wrapper = (TableModelWrapper<?>) model;
            return wrapper.getModelRow(viewRow);
        }
        return viewRow; // assume no filtering, as we don't know how to handle it anyway
    }

    private static void writeAllModelData(PrintWriter writer, JTable table, TableModel model,
            TaskMonitor monitor) {

        monitor.setMessage("Writing model...");
        monitor.initialize(model.getRowCount());

        int columnCount = table.getColumnCount();
        for (int row = 0; row < model.getRowCount(); ++row) {
            if (monitor.isCancelled()) {
                break;
            }
            monitor.setProgress(row);
            for (int col = 0; col < columnCount; col++) {
                if (monitor.isCancelled()) {
                    break;
                }

                String value = getColumnValue(table, model, row, col);
                if (value == null) {
                    // not sure how this could happen...has the model changed out from under us?
                    value = "";
                }

                writeYaraSignature(writer, value, value, value, value, value, value, value, monitor);
            }
            // two new lines for visual separation
            writeNewLine(writer);
            writeNewLine(writer);
        }
    }

    private static void writeNewLine(PrintWriter writer) {
        writer.print('\n');
    }

    /**
     * Write the given fileds into YARA format and save the result into
     * the file specified by the writer.
     */
    private final static void writeYaraSignature(PrintWriter writer, String filename_value, String md5_value, String bytes_value, String addr_value, String pichash_value, String numbytes_value, String numinsns_value, TaskMonitor monitor) {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String todays_date = formatter.format(calendar.getTime());
    
        StringBuilder yarasig = new StringBuilder();
        /*
        rule Func_md5_[MD5]_[ADDR]
        {
        strings:
            // File [FILENAME] @ [ADDR] ([DATE])
            // string $md5_[MD5]_[ADDR] contains [B] bytes and [I] instructions
            $md5_[MD5]_[ADDR] = { [BYTES] }
        condition:
            all of them
        }   
        */
        yarasig.append(String.format("rule Func_md5_%1$s_%2$s\n", md5_value, addr_value));
        yarasig.append("{\n");
        yarasig.append("strings:\n");
        yarasig.append(String.format("\t// File '%1$s' @ %2$s (%3$s)\n", filename_value, addr_value, todays_date));
        yarasig.append(String.format("\t// PIC Hash %1$s\n", pichash_value));
        yarasig.append(String.format("\t// string $md5_%1$s_%2$s contains %3$s bytes and %4$s instructions\n", md5_value, addr_value, numbytes_value, numinsns_value));
        yarasig.append(String.format("\t$md5_%1$s_%2$s = { %3$s }\n", md5_value, addr_value, bytes_value));
        yarasig.append("condition:\n");
        yarasig.append("\tall of them\n");
        yarasig.append("}\n");
        writer.print(yarasig.toString());
    }

    private static class ConvertTask extends Task {
        private final GhidraTable table;
        private TableModel model;
        private GTableColumnModel columnModel;

        private File file;
        private List<Integer> columns = new ArrayList<Integer>();

        ConvertTask(File file, GhidraTable table, TableModel model) {
            super(GTableToYARA.TITLE, true, true, true);
            this.file = file;
            this.table = table;
            this.columnModel = (GTableColumnModel) table.getColumnModel();
            this.model = model;
        }

        ConvertTask(File file, GhidraTable table, TableModel model, List<Integer> columns) {
            super(GTableToYARA.TITLE, true, true, true);
            this.file = file;
            this.table = table;
            this.columns = columns;
            this.columnModel = (GTableColumnModel) table.getColumnModel();
            this.model = model;
        }

        @Override
        public void run(TaskMonitor monitor) {
            try {
                GTableToYARA.writeYARA(file, table, columnModel, model, columns, monitor);
            }
            catch (IOException e) {
                Msg.error(GhidraTable.class.getName(), e.getMessage());
            }

            DockingWindowManager manager = DockingWindowManager.getInstance(table);
            if (manager != null) { // can happen during testing
                manager.setStatusText("Finished writing YARA data");
            }
        }
    }
}
