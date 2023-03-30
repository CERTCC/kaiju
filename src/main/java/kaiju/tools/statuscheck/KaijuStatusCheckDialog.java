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
package kaiju.tools.statuscheck;

import java.awt.*;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import resources.ResourceManager;

import kaiju.common.*;

import com.microsoft.z3.Version;

class KaijuStatusCheckDialog extends DialogComponentProvider {
    private static final int _24_HOURS = 86400000;
    private KaijuStatusCheckPlugin plugin;
    private JCheckBox showTipsCheckbox;
    private JButton nextTipButton;
    private JButton closeButton;
    private JTextArea tipArea;
    private int tipIndex = 0;
    private List<String> tips;
    
    private static boolean z3LibsFound;
    
    static {
        try {
            KaijuNativeLibraryLoaderUtil.loadLibrary("z3");
            KaijuNativeLibraryLoaderUtil.loadLibrary("z3java");
            z3LibsFound = true;
        } catch (Throwable t) {
            z3LibsFound = false;
        }
    }

    KaijuStatusCheckDialog(KaijuStatusCheckPlugin plugin, List<String> tips) {
        super("Kaiju Status Check", false, false, true, false);

        this.plugin = plugin;
        this.tips = tips;

        JLabel z3VerLabel = new GLabel("", ResourceManager.loadImage("images/red-x.png"), SwingConstants.LEFT);
        //boolean z3LibsFound = false;
        try {
            z3VerLabel.setText("Z3 loaded successfully. Using Z3 version: " + Version.getFullVersion());
            // by calling getFullVersion() above, we are implicitly
            // checking that Z3 is loaded. If not, it will throw an exception.
            //z3LibsFound = true;
        } catch (NoClassDefFoundError nce) {
            z3VerLabel.setText("Warning: NoClassDefFoundError while loading Z3. Some tools like Ghihorn will be disabled.");
        } catch (UnsatisfiedLinkError e) {
            z3VerLabel.setText("Warning: Z3 libraries not loaded. Some tools like Ghihorn will be disabled.");
        }
        
        if (z3LibsFound) {
            z3VerLabel.setIcon(ResourceManager.loadImage("images/green-check.png"));
        }
        
        // if couldn't load Z3, disable Ghihorn
        if (!z3LibsFound) {
            // TODO? can we do this here?
            // in meantime, ghihorn turns off its menu item if can't find library
        }

        JPanel statusPanel = new JPanel(new GridLayout(1, 1));
        statusPanel.setBorder(BorderFactory.createTitledBorder("Kaiju Status"));
        statusPanel.add(z3VerLabel);

        if (tips.isEmpty()) {
            tips.add("Could not find any tips!");
        }

        ImageIcon tipIcon = ResourceManager.loadImage("images/kaiju-icon.png");

        tipArea = new JTextArea(6, 40);
        tipArea.setEditable(false);
        tipArea.setFont(new Font("dialog", Font.PLAIN, 12));
        tipArea.setWrapStyleWord(true);
        tipArea.setLineWrap(true);
        tipArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JScrollPane tipScroll = new JScrollPane(tipArea);
        tipScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        tipScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        tipScroll.setBorder(null);
        tipScroll.setPreferredSize(tipArea.getPreferredSize());

        showTipsCheckbox = new GCheckBox("Show Kaiju Status on Startup?");
        showTipsCheckbox.setSelected(true); // TODO (FixMe) Moved this before its listener to prevent project save for now.
        showTipsCheckbox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                showTipsChanged();
            }
        });

        nextTipButton = new JButton("Next Tip");
        nextTipButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                incrementTipIndex();
                loadNextTip();
            }
        });
        addButton(nextTipButton);

        closeButton = new JButton("Close");
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                close();
            }
        });
        addButton(closeButton);

        JPanel panel = new JPanel(new BorderLayout());
        Border panelBorder =
            BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10),
                BorderFactory.createLineBorder(Color.BLACK));
        panel.setBorder(panelBorder);
        panel.setBackground(Color.WHITE);

        JLabel label = new GLabel("Welcome to CERT Kaiju", tipIcon, SwingConstants.LEFT);
        label.setFont(new Font("dialog", Font.BOLD, 12));
        panel.add(label, BorderLayout.NORTH);

        panel.add(tipScroll, BorderLayout.CENTER);
        
        panel.add(statusPanel, BorderLayout.SOUTH);

        JPanel panel2 = new JPanel(new BorderLayout(1, 1));
        panel2.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel2.add(panel, BorderLayout.CENTER);
        panel2.add(showTipsCheckbox, BorderLayout.SOUTH);

        addWorkPanel(panel2);
    }

    private void showTipsChanged() {
        plugin.writePreferences();
    }

    private static long lastTipTime = 0;

    void show(Component parent) {
        long now = System.currentTimeMillis();
        if (now - lastTipTime > _24_HOURS) {
            doShow(parent);
        }
        lastTipTime = now;
    }

    void doShow(Component parent) {
        loadNextTip();
        DockingWindowManager.showDialog(parent, this);
    }

    private void incrementTipIndex() {
        tipIndex = (++tipIndex) % tips.size();
        plugin.writePreferences();
    }

    private void loadNextTip() {
        if (tips.isEmpty()) {
            return;
        }
        if (tipIndex < 0 || tipIndex > tips.size() - 1) {
            return;
        }
        String tip = tips.get(tipIndex);
        tipArea.setText(tip);
    }

    int getTipIndex() {
        return tipIndex;
    }

    int getNumberOfTips() {
        return tips.size();
    }

    boolean showStatus() {
        return showTipsCheckbox.isSelected();
    }

    void setTipIndex(int tipIndex) {
        this.tipIndex = tipIndex;
        loadNextTip();
    }

    void setShowTips(boolean showTips) {
        showTipsCheckbox.setSelected(showTips);
    }
}
