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
package kaiju.gradle

import java.util.HashMap

import org.commonmark.node.*;
import org.commonmark.renderer.*;
import org.commonmark.renderer.html.*;

public class GhidraHtmlNodeRenderer extends CoreHtmlNodeRenderer implements NodeRenderer {

    //protected final HtmlNodeRendererContext context;
    private final HtmlWriter html;

    public GhidraHtmlNodeRenderer(HtmlNodeRendererContext context) {
        super(context);
        this.html = context.getWriter();
    }

    @Override
    public void visit(Document document) {
        html.tag("html");
        html.line();
        html.tag("head");
        html.line();
        html.tag("title");
        html.text("Kaiju Documentation");
        html.tag("/title");
        html.line();
        // <LINK rel="stylesheet" type="text/css" href="../../shared/Frontpage.css">
        HashMap<String,String> linkattrs = new HashMap<>();
        linkattrs.put("rel","stylesheet");
        linkattrs.put("type","text/css");
        linkattrs.put("href","help/shared/DefaultStyle.css");
        html.tag("link", linkattrs);
        html.line();
        html.tag("/head");
        html.line();
        html.line();
        // render rest of the document
        visitChildren(document);
        html.tag("/html");
    }
    
    // based on code from CommonMark implementation
    @Override
    public void visit(Image image) {
        String url = image.getDestination();

        AltTextVisitor altTextVisitor = new AltTextVisitor();
        image.accept(altTextVisitor);
        String altText = altTextVisitor.getAltText();

        Map<String, String> attrs = new LinkedHashMap<>();
        if (context.shouldSanitizeUrls()) {
            url = context.urlSanitizer().sanitizeImageUrl(url);
        }

        attrs.put("src", context.encodeUrl(url));
        attrs.put("alt", altText);
        if (image.getTitle() != null) {
            attrs.put("title", image.getTitle());
        }
        
        // Ghidra specific default
        attrs.put("border", "1");

        Map<String, String> pattrs = new LinkedHashMap<>();
        pattrs.put("align","center");
        
        html.tag("p", pattrs);
        html.tag("img", getAttrs(image, "img", attrs), true);
        html.tag("/p");
        
        // use the alttext as an image caption
        pattrs.put("style","font-style: italic;");
        html.tag("p", pattrs);
        html.text(altText);
        html.tag("/p");
    }
    
    // below this line: boilerplate from CommonMark
    
    private Map<String, String> getAttrs(Node node, String tagName) {
        return getAttrs(node, tagName, Collections.<String, String>emptyMap());
    }

    private Map<String, String> getAttrs(Node node, String tagName, Map<String, String> defaultAttributes) {
        return context.extendAttributes(node, tagName, defaultAttributes);
    }

    private static class AltTextVisitor extends AbstractVisitor {

        private final StringBuilder sb = new StringBuilder();

        String getAltText() {
            return sb.toString();
        }

        @Override
        public void visit(Text text) {
            sb.append(text.getLiteral());
        }

        @Override
        public void visit(SoftLineBreak softLineBreak) {
            sb.append('\n');
        }

        @Override
        public void visit(HardLineBreak hardLineBreak) {
            sb.append('\n');
        }
    }

}
