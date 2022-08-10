/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//package ghidra.app.plugin.core.data;
package kaiju;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.data.DataPlugin;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.AlignmentDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

import kaiju.common.di.GhidraDI;

import java.lang.reflect.*;
//     try
//     {
//       c.getDeclaredMethod("allowSwingToProcessEvents");
//       try {
//         c.getDeclaredMethod("allowSwingToProcessEvents").invoke(this);
//       } catch (Exception e) {
//         Msg.warn(this, "Error invoking function.");
//     } catch(NoSuchMethodException e) {
//       Msg.warn(this, "Unable to locate allowSwingToProcessEvents. The GUI may be irresponsive.");
//     }

/**
 * An action that allows the user to set an Alignment data type.
 */
public class AlignmentAction extends DockingAction {

    private DataPlugin plugin;
    private static final KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_A, 0);
    private final static String ACTION_NAME = "Create Alignment";
    private static final String[] CREATE_ALIGNMENT_POPUP_MENU =
        new String[] { "Data", "Create Alignment..." };

    public AlignmentAction(DataPlugin plugin) {
        super(ACTION_NAME, plugin.getName(), KeyBindingType.SHARED);
        this.plugin = plugin;

        setPopupMenuData(new MenuData(CREATE_ALIGNMENT_POPUP_MENU, "BasicData"));
        setEnabled(true);

        initKeyStroke(KEY_BINDING);
    }

    private void initKeyStroke(KeyStroke keyStroke) {
        if (keyStroke == null) {
            return;
        }

        setKeyBindingData(new KeyBindingData(keyStroke));
    }

    @Override
    public void actionPerformed(ActionContext context) {
        ListingActionContext listingContext = (ListingActionContext) context.getContextObject();
        DataType dataType = new AlignmentDataType();
        if (dataType != null) {
			Class<?> c = null;
			try {
				c = Class.forName("ghidra.app.plugin.core.data.DataPlugin");
			} catch (ClassNotFoundException e) {
				//TODO
			}
			Class[] cArg = new Class[3];
			cArg[0] = DataType.class;
			cArg[1] = ListingActionContext.class;
			cArg[2] = boolean.class;
			if (GhidraDI.isPriorToGhidraMinorVersion("10.2")) {
				try
				{
					c.getDeclaredMethod("createData", cArg);
					try {
						c.getDeclaredMethod("createData").invoke(plugin, dataType, listingContext, false);
					} catch (Exception e) {
						//Msg.warn(this, "Error invoking function.");
					}
				} catch(NoSuchMethodException e) {
					//Msg.warn(this, "Unable to locate createData with appropriate parameters. The GUI may be irresponsive.");
				}
			} else {
				//plugin.createData(dataType, listingContext, false);
				// for Ghidra 10.2+
				try
				{
					c.getDeclaredMethod("createData");
					try {
						c.getDeclaredMethod("createData").invoke(plugin, dataType, listingContext, false, false);
					} catch (Exception e) {
						//Msg.warn(this, "Error invoking function.");
					}
				} catch(NoSuchMethodException e) {
					//Msg.warn(this, "Unable to locate createData with appropriate parameters. The GUI may be irresponsive.");
				}
			}
        }
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        Object contextObject = context.getContextObject();
        if (contextObject instanceof ListingActionContext) {
            return plugin.isCreateDataAllowed(((ListingActionContext) contextObject));
        }
        return false;
    }
}
