/***
 * CERT Kaiju Copyright 2021 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
 * FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
 * EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 * PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
 * MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
 * TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Released under a BSD (SEI)-style license, please see LICENSE.md or contact permission@sei.cmu.edu
 * for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
 * distribution. Please see Copyright notice for non-US Government use and distribution.
 *
 * Carnegie Mellon (R) and CERT (R) are registered in the U.S. Patent and Trademark Office by
 * Carnegie Mellon University.
 *
 * This Software includes and/or makes use of the following Third-Party Software subject to its own
 * license: 1. OpenJDK (http://openjdk.java.net/legal/gplv2+ce.html) Copyright 2021 Oracle. 2.
 * Ghidra (https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE) Copyright 2021
 * National Security Administration. 3. GSON (https://github.com/google/gson/blob/master/LICENSE)
 * Copyright 2020 Google. 4. JUnit (https://github.com/junit-team/junit5/blob/main/LICENSE.md)
 * Copyright 2020 JUnit Team. 5. Gradle (https://github.com/gradle/gradle/blob/master/LICENSE)
 * Copyright 2021 Gradle Inc. 6. markdown-gradle-plugin
 * (https://github.com/kordamp/markdown-gradle-plugin/blob/master/LICENSE.txt) Copyright 2020 Andres
 * Almiray. 7. Z3 (https://github.com/Z3Prover/z3/blob/master/LICENSE.txt) Copyright 2021 Microsoft
 * Corporation. 8. jopt-simple (https://github.com/jopt-simple/jopt-simple/blob/master/LICENSE.txt)
 * Copyright 2021 Paul R. Holser, Jr.
 *
 * DM21-0792
 */
package kaiju.common;

import java.lang.reflect.InvocationTargetException;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;

public class KaijuGhidraCompat {
    
    /**
     * This is a helper function to return the ToolOptions for a specific service.
     * @param sp The service provider
     * @param serviceNAme The specific service
     * @return The ToolOptions for service
     * @throws SecurityException
     * @throws InvocationTargetException
     * @throws IllegalArgumentException
     **/
    public static ToolOptions getToolOptions(ServiceProvider sp, String serviceName) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException {           
        Class<?> OptionsServiceClass = null;

        String[] names = {"ghidra.framework.plugin.util.OptionsService", "ghidra.framework.plugintool.util.OptionsService", "docking.options.OptionsService"};

        for (var name: names) {
            try {
                OptionsServiceClass = Class.forName(name);
                break;
            }
            catch (ClassNotFoundException e) {
                continue;
            }
        }

        if (OptionsServiceClass == null) {
            throw new ClassNotFoundException("Could not find OptionsService class");
        }

        var optionService = sp.getService(OptionsServiceClass);

        if (optionService != null) {
            ToolOptions opt = (ToolOptions) OptionsServiceClass.getMethod("getOptions", String.class).invoke(optionService, serviceName);
            return opt;
        } else {
            throw new RuntimeException("Could not get options for service " + serviceName);
        }        
    }
}
