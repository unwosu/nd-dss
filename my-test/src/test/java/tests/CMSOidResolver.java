/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package tests;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;


/**
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CMSOidResolver {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(CMSOidResolver.class);

    final Properties oidDictionary;

    public CMSOidResolver() {
        try {
            oidDictionary = new Properties();
            oidDictionary.load(getClass().getResourceAsStream("/oid.properties"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Map.Entry<String, String> oidLookup(ASN1ObjectIdentifier oid) throws IOException {

        String oidName = oidDictionary.getProperty(oid.getId() + ".name", null);
        String oidDescription = oidDictionary.getProperty(oid.getId() + ".description", null);

        if (oidName == null) {

            String url = "http://oid-info.com/get/";

            final CommonsDataLoader commonsHttpDataLoader = new CommonsDataLoader();
            final String fullUrl = url + oid.getId();
            LOG.info("fetch " + fullUrl);
            final byte[] bytes = commonsHttpDataLoader.get(fullUrl);
            String result = new String(bytes);
            oidName = getOidName(result);
            oidDescription = getOidDescription(result);

            oidDictionary.put(oid.getId() + ".name", oidName == null ? "n/a" : oidName);
            oidDictionary.put(oid.getId() + ".description", oidDescription == null ? "n/a" : oidDescription);

            saveAndPrintNewDictionary();
        }

        return new AbstractMap.SimpleEntry<String, String>(oidName, oidDescription);

    }

    private void saveAndPrintNewDictionary() throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        oidDictionary.store(out, "OID loaded from http://oid-info.com/");
        LOG.info("*********** PLEASE SAVE THIS NEW DICTIONARY IN test/resources/oid.properties *******************");
        LOG.info(out.toString());
        LOG.info("******************************");

    }

    private String getOidName(String result) {
        Pattern pattern = Pattern.compile(".*<title>OID repository - (\\{.+})</title>.*", Pattern.DOTALL);
        final Matcher matcher = pattern.matcher(result);
        if (matcher.matches()) {
            String oidDescription = matcher.group(1);
            return oidDescription;
        } else {
            LOG.info("OID not found in result");
            return null;
        }
    }

    private String getOidDescription(String result) throws IOException {
        try {
            Scanner scanner = new Scanner(result);
            String line;
            StringBuilder stringBuilder = new StringBuilder();
            boolean started = false;
            while ((line = scanner.nextLine()) != null) {
                if (started) {
                    stringBuilder.append(line);
                }
                if (line.contains("<br><b>Description</b>:")) {
                    started = true;
                }
                if (started && line.contains("/tr")) {
                    break;
                }
            }

            Pattern pattern = Pattern.compile(".*<td colspan=3 align=\"left\" width=\"315\">(.+)</td>.*", Pattern.DOTALL);
            final Matcher matcher = pattern.matcher(stringBuilder.toString());
            if (matcher.matches()) {
                String oidDescription = matcher.group(1);
                final Html2Text html2Text = new Html2Text();
                html2Text.parse(new StringReader(oidDescription));
                return html2Text.getText();
            } else {
                LOG.info("OID not found in stringBuilder" + stringBuilder.toString());
                return null;
            }
        } catch (Exception e) {
            LOG.info("OID not found. " + e.getMessage());
            return null;
        }
    }

    private class Html2Text extends HTMLEditorKit.ParserCallback {
        StringBuffer s;

        public Html2Text() {
        }

        public void parse(Reader in) throws IOException {
            s = new StringBuffer();
            ParserDelegator delegator = new ParserDelegator();
            // the third parameter is TRUE to ignore charset directive
            delegator.parse(in, this, Boolean.TRUE);
        }

        public void handleText(char[] text, int pos) {
            s.append(text);
        }

        public String getText() {
            return s.toString();
        }

    }
}
