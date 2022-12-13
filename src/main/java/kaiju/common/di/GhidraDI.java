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
package kaiju.common.di;

import ghidra.framework.Application;

import java.util.ArrayList;
import java.util.List;

public class GhidraDI {
    
   /**
     * Returns the version of the Ghidra being run.
     * This is the version check GhidraScript uses,
     * duplicated here
     * @return the version of the Ghidra being run,
     *         in the format: "x.y.z".
     */
   public static final String getGhidraVersionStr() {
      //TODO: what if version is e.g. 10.2, no "z"? can we auto-add 0?
      return Application.getApplicationVersion();
   }
     
   public static final boolean isAtLeastGhidraMinorVersion(String version) {
      Integer[] current = versionStrToIntList(getGhidraVersionStr());
      Integer[] given = versionStrToIntList(version);
      return compareGhidraVersions(current, given, "minor") >= 0;
   }
     
   public static final boolean isNewerThanGhidraMinorVersion(String version) {
      return isAtLeastGhidraMinorVersion(version);
   }
     
   public static final boolean isPriorToGhidraMinorVersion(String version) {
      String ghidra = getGhidraVersionStr();
      Integer[] current = versionStrToIntList(ghidra);
      Integer[] given = versionStrToIntList(version);
      return compareGhidraVersions(current, given, "minor") < 0;
   }
   
   public static final int compareGhidraVersions(Integer[] one, Integer[] two, String digit) {
      // we assume both one and two are Integer[3] arrays
      int comparison = 0;
      // first test the major versions, return if that's all we needed
      if (one[0] > two[0]) {
         comparison = 1;
      } else if (one[0] == two[0]) {
         comparison = 0;
      } else {
         // less than
         comparison = -1;
      }
      // next test minor versions, but only if major versions is greater than or equal
      if (digit.equals("minor") || digit.equals("bugfix")) {
         if (comparison >= 0) {
            if (one[1] > two[1]) {
               comparison = 1;
            } else if (one[1] == two[1]) {
               comparison = 0;
            } else {
               // less than
               comparison = -1;
            }
         }
         
         // if we're testing bugfixes, check it now
         if (digit.equals("bugfix")) {
            if (comparison >= 0) {
               if (one[2] > two[2]) {
                  comparison = 1;
               } else if (one[2] == two[2]) {
                  comparison = 0;
               } else {
                  // less than
                  comparison = -1;
               }
            }
         }
      }
      return comparison;
   }
     
   /**
     * Returns the version of the Ghidra being run as a list of Strings.
     * @return the version of the Ghidra being run,
     *         in the format: ["x", "y", "z"].
     */
   public static final String[] versionStrToStrList(String version) {
      // escape the period or it will be treated as a regex wildcard!
      String[] ver = version.split("\\.", 3);
      // we may not have ended up with three number if the version is e.g. "10.2",
      // TODO: is it ok to assume the bugfix is 0 if we only have two items in the array?
      if (ver.length == 2) {
         // try to split it again after adding to the version string!
         ver = (version + ".0").split("\\.", 3);
      }
      return ver;
   }
     
   /**
     * Returns the version of the Ghidra being run as a list of Integers.
     * @return the version of the Ghidra being run,
     *         in the format: ["x", "y", "z"].
     */
   public static final Integer[] versionStrToIntList(String version) {
      String[] verlist = versionStrToStrList(version);
      List<Integer> verintlist = new ArrayList<Integer>();
      for (String a : verlist) {
         verintlist.add(Integer.parseInt(a));
      };
      // this is weird syntax to say:
      // convert to array with typing of an array of Integer
      return verintlist.toArray(new Integer[3]);
   }

}
