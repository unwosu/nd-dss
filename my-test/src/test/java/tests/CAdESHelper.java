/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.OID;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class CAdESHelper {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESHelper.class);

	/**
	 * The empty String {@code ""}.
	 *
	 * @since 2.0
	 */
	public static final String EMPTY = "";

	/**
	 * <p>The maximum size to which the padding constant(s) can expand.</p>
	 */
	private static final int PAD_LIMIT = 8192;

	/**
	 * Used to build output as Hex
	 */
	private static final char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	/**
	 * Used to build output as Hex
	 */
	private static final char[] DIGITS_UPPER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

	private static final boolean SHOW_HEX_CMS_SIGNED_DATA = false;

	public static CMSOidResolver cAdESSignatureOidReader = new CMSOidResolver();

	public static String helperResolvePKCSIdentifier(String OID) throws DSSException {
		try {
			final Map.Entry<String, String> oidNameDescription = cAdESSignatureOidReader.oidLookup(new ASN1ObjectIdentifier(OID));

			return oidNameDescription.getValue() + " " + oidNameDescription.getKey();
		} catch (IOException e) {
			throw new DSSException();
		}
	}

	@SuppressWarnings("rawtypes")
	public static void dumpCMSSignedDocument(DSSDocument cmsDoc) {
		dumpCMSSignedDocument(cmsDoc, System.out);
	}

	@SuppressWarnings("rawtypes")
	public static void dumpCMSSignedDocument(DSSDocument cmsDoc, PrintStream out) {
		InputStream is = null;
		try {
			is = cmsDoc.openStream();
			CMSSignedData cmsSignedData = new CMSSignedData(is);
			dumpCMSSignedDocument(cmsSignedData, "", out);
		} catch (Exception e) {
			throw new DSSException(e);
		} finally {

			org.apache.commons.io.IOUtils.closeQuietly(is);
		}
	}

	public static void dumpCMSSignedDocument(CMSSignedData cmsSignedData) throws DSSException {
		dumpCMSSignedDocument(cmsSignedData, "", System.out);
	}

	public static void dumpCMSSignedDocument(CMSSignedData cmsSignedData, String indentString, PrintStream out) throws DSSException {
		try {
			byte[] content = (cmsSignedData.getSignedContent() != null) ? (byte[]) cmsSignedData.getSignedContent().getContent() : null;
			ContentInfo contentinfo = cmsSignedData.toASN1Structure();
			out.printf("%sCMSSignedData: Version %d%n", indentString, cmsSignedData.getVersion());
			indentString = indentString + "!  ";
			if (SHOW_HEX_CMS_SIGNED_DATA) {
				final byte[] encodedSmsSignedData = cmsSignedData.getEncoded();
				out.printf("%s    Hex CMSSignedData: %s%n", indentString, encodeHexString(encodedSmsSignedData));
			}
			out.printf("%s    Signed ContentType OID: %s%n", indentString, helperResolvePKCSIdentifier(cmsSignedData.getSignedContentTypeOID()));
			if (content != null) {
				if (content.length <= 100) {
					out.printf("%s    SignedContent (%d bytes): %s%n", indentString, new String(content).length(), encodeHexString(content));
				} else {
					out.printf("%s    SignedContent (%d bytes): %s.......... *truncated*%n", indentString, new String(content).length(),
						  new String(content).substring(0, Math.min(content.length, 4)));
				}
			} else {
				out.printf("%s    SignedContent : [Detached]%n", indentString);
			}
			out.printf("%s    ContentInfo:%n", indentString);
			out.printf("%s        ContentType OID: %s%n", indentString, helperResolvePKCSIdentifier(contentinfo.getContentType().getId()));

			out.printf("%s    Certificates:%n", indentString);
			CollectionStore store = (CollectionStore) cmsSignedData.getCertificates();
			Collection certs = store.getMatches(null);
			for (Object c : certs) {

				X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) c;
				final CertificateToken x509Certificate = DSSUtils.loadCertificate(x509CertificateHolder.getEncoded());
				final int dssId = 1;//CertificateIdentifier.getId(x509Certificate);
				final X500Name subject = x509CertificateHolder.getSubject();
				final BigInteger serialNumber = x509CertificateHolder.getSerialNumber();
				final X500Name issuer = x509CertificateHolder.getIssuer();
				out.printf("%s        Certificate: DSS[%s] / SN: %s / SN: %s / Issued by: %s%n", indentString, dssId, subject, serialNumber, issuer);
			}

			out.printf("%s    CRLs:%n", indentString);
			store = (CollectionStore) cmsSignedData.getCRLs();
			Collection crls = store.getMatches(null);
			for (Object c : crls) {
				if (c instanceof X509CRLHolder) {
					X509CRLHolder x509CRLHolder = (X509CRLHolder) c;
					final X500Name issuer = x509CRLHolder.getIssuer();
					final int size = x509CRLHolder.getRevokedCertificates().size();
					final X509CRL x509CRL = DSSUtils.toX509CRL(x509CRLHolder);
					final Date thisUpdate = x509CRL.getThisUpdate();
					final String dateString = DSSUtils.formatInternal(thisUpdate);
					out.printf("%s        CRL: %d entries / Issued by: %s on %s%n", indentString, size, issuer, dateString);
				} else if (c instanceof CertificateList) {
					CertificateList certificateList = (CertificateList) c;
					out.printf("%s        CRL: %d entries / Issued by: %s on %s%n", indentString, certificateList.getRevokedCertificates().length, certificateList.getIssuer(),
						  certificateList.getThisUpdate().getDate().toString());

				} else {
					out.printf("%s        CRL: UNKNOWN TYPE %s%n", indentString, c.getClass().getName());
				}
			}

			{
				final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
				final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
				final ASN1Encodable[] matches = (ASN1Encodable[]) otherRevocationInfoMatches.toArray(new ASN1Encodable[otherRevocationInfoMatches.size()]);
				for (final ASN1Encodable asn1Encodable : matches) {
					final BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(asn1Encodable);
					final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOcspResponse);
					out.printf("%s        BasicOCSP: %d entries / Issued on %s%n", indentString, basicOCSPResp.getCerts().length, basicOCSPResp.getProducedAt().toString());
				}
			}
			{

				final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
				final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
				final ASN1Encodable[] matches = (ASN1Encodable[]) otherRevocationInfoMatches.toArray(new ASN1Encodable[otherRevocationInfoMatches.size()]);
				for (final ASN1Encodable asn1Encodable : matches) {
					final OCSPResponse ocspResponse = OCSPResponse.getInstance(asn1Encodable);
					final OCSPResp ocspResp = new OCSPResp(ocspResponse);
					BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
					out.printf("%s        riOCSP: %d entries / Issued on %s%n", indentString, basicOCSPResp.getCerts().length, basicOCSPResp.getProducedAt().toString());
				}
			}

            /* Attribute certificates: out-of-scope for now */
			for (Object o : cmsSignedData.getSignerInfos().getSigners()) {
				SignerInformation si = (SignerInformation) o;
				SignerId sid = si.getSID();
				int indentSize = 1;
				out.printf("%sSignerInformation:%n", indentString, repeat("  ", indentSize));
				String subIndentString = indentString + "* " + repeat("  ", indentSize + 1);
				out.printf("%sVersion: %d%n", subIndentString, si.getVersion());
				out.printf("%sSignerID: Issuer: %s / SN: %s / SKI: %s/ %n", subIndentString, String.valueOf(sid.getIssuer()), sid.getSerialNumber(),
					  sid.getSubjectKeyIdentifier() == null ? null : encodeHexString(sid.getSubjectKeyIdentifier()));
				out.printf("%sContentType: %s%n", subIndentString, helperResolvePKCSIdentifier(si.getContentType().toString()));
				out.printf("%sDigest Alg OID: %s%n", subIndentString, helperResolvePKCSIdentifier(si.getDigestAlgOID()));
				out.printf("%sEncryption Alg OID: %s%n", subIndentString, helperResolvePKCSIdentifier(si.getEncryptionAlgOID()));
				out.printf("%sSignature: %s%n", subIndentString, new DEROctetString(si.getSignature()).toString());

				showSignedAttributes(si.getSignedAttributes(), subIndentString, out);
				showUnsignedAttributes(si.getUnsignedAttributes(), subIndentString, out);
			}
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	private static void showSignedAttributes(AttributeTable signedAttributes, String indentPrefix, PrintStream out) throws Exception {
		if (signedAttributes == null) {
			return;
		}
		final ASN1EncodableVector asn1EncodableVector = signedAttributes.toASN1EncodableVector();
		showSignedAttributes(asn1EncodableVector, indentPrefix, out);
	}

	private static void showSignedAttributes(ASN1EncodableVector asn1EncodableVector, String indentPrefix, PrintStream out) throws ParseException {
		for (int attrIdx = 0; attrIdx < asn1EncodableVector.size(); attrIdx++) {
			Attribute attr = (Attribute) asn1EncodableVector.get(attrIdx);
			String identString = indentPrefix + "| ";
			out.printf("%sSignedAttribute: %s%n", identString, helperResolvePKCSIdentifier(attr.getAttrType().toString()));
			identString += "  ";
			if (attr.getAttrType().getId().equals("1.2.840.113583.1.1.8")) {
				out.printf("%sAttribute is Adobe's Revocation Information attribute (OID 1.2.840.113583.1.1.8)%n", identString);
				out.printf("%s%s%n", identString, attr.getAttrValues().toString());

                /*
                 * Adobe Revocation Information Attribute is defined in:
                 * http://www.adobe.com/content/dam/Adobe/en/devnet/acrobat/pdfs/PDF32000_2008.pdf, §12.8.3.3.2.
                 * Incidentally, its type, RevocationInfoArchival, happens to be similar to ETSI's RevocationValues
                 * defined in TS 101 733 (CAdES), §6.3.4, which is known to BouncyCastle!
                 */
				ASN1Sequence asn1Sequence = (ASN1Sequence) attr.getAttrValues().getObjectAt(0);
				try {
					// TODO (pades): parsing fails here for /hello-world-pades.pdf. Looks how iText parse it in PdfPkcs7 class, that looks not so simple. See PadesOCSPSource and PadesCRLSource comments too.
					RevocationValues revValues = RevocationValues.getInstance(asn1Sequence);
					out.printf("%sRevocationValues: %d CRL(s), %d OCSP response(s)%n", identString, revValues.getCrlVals().length, revValues.getOcspVals().length);
					for (CertificateList crlHolder : revValues.getCrlVals()) {
						out.printf("%s - CertificateList (CRL): %d entries / Issued by: %s on %s%n", identString, crlHolder.getRevokedCertificates().length, crlHolder.getIssuer(),
							  crlHolder.getThisUpdate().getDate().toString());
					}
					for (BasicOCSPResponse ocspHolder : revValues.getOcspVals()) {
						out.printf("%s - BasicOCSPResponse: %d response(s), responder: %s on %s%n", identString, ocspHolder.getTbsResponseData().getResponses().size(),
							  ocspHolder.getTbsResponseData().getResponderID().getName().toString(), ocspHolder.getTbsResponseData().getProducedAt().getDate().toString());
					}
				} catch (IllegalArgumentException e) {
					out.printf("%s - FAILURE parsing Adobe Revocation Information Attribute %s%n", identString, e.getMessage());
				}

			} else if (attr.getAttrType().getId().equals("1.2.840.113549.1.9.5")) {
				for (final ASN1Encodable asn1Encodable : attr.getAttributeValues()) {
					final Time time = Time.getInstance(asn1Encodable);
					out.printf("%sValue (%s): %s%n", identString, asn1Encodable.getClass().getSimpleName(), time.getDate());
				}
			} else {
				out.printf("%sValue:%s%n", identString, attr.getAttrValues().toString());
			}

		}
	}

	private static void showUnsignedAttributes(AttributeTable unsignedAttributes, String indentPrefix, PrintStream out) throws Exception {
		if (unsignedAttributes == null) {
			out.printf("%sUnsignedAttribute: NULL%n", indentPrefix);
			return;
		}
		if (unsignedAttributes.size() == 0) {
			out.printf("%sUnsignedAttribute: Empty (NOT ALLOWED, MUST BE NULL OR AT LEAST ONE VALUE)%n", indentPrefix);
			return;
		}
		final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
		for (int attrIdx = 0; attrIdx < asn1EncodableVector.size(); attrIdx++) {
			Attribute attr = (Attribute) asn1EncodableVector.get(attrIdx);
			String indentString = indentPrefix + "| ";
			out.printf("%sUnsignedAttribute: %s%n", indentString, helperResolvePKCSIdentifier(attr.getAttrType().toString()));
			indentString += "  ";
			if (attr.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) || attr.getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp) || attr
				  .getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp) || attr.getAttrType()
				  .equals(PKCSObjectIdentifiers.id_aa.branch("48"))/* id_aa_ets_archiveTimestampV2 */ || (attr.getAttrType().getId()
				  .equals(OID.id_aa_ets_archiveTimestampV3.getId()))) {

				try {
					final byte[] encoded = attr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded();
					final CMSSignedData signedData = new CMSSignedData(encoded);
					TimeStampToken timeStampToken = new TimeStampToken(signedData);
					out.printf("%sTimeStampToken: %s by %s%n", indentString, timeStampToken.getTimeStampInfo().getGenTime().toString(),
						  (timeStampToken.getTimeStampInfo().getTsa() != null) ? timeStampToken.getTimeStampInfo().getTsa().toString() : timeStampToken.getSID().getIssuer()
								.toString() + " / SN: " + timeStampToken.getSID().getSerialNumber().toString());
					dumpCMSSignedDocument(new CMSSignedData(timeStampToken.getEncoded()), indentString, out);
				} catch (IOException e) {
					e.printStackTrace();
				} catch (CMSException e) {
					e.printStackTrace();
				} catch (TSPException e) {
					e.printStackTrace();
				} catch (DSSException e) {
					e.printStackTrace();
				}
			} else if (attr.getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_certificateRefs)) {
				ASN1Sequence completeCertificateRefs = (ASN1Sequence) attr.getAttrValues().getObjectAt(0);
				for (int i1 = 0; i1 < completeCertificateRefs.size(); i1++) {
					OtherCertID otherCertID = OtherCertID.getInstance(completeCertificateRefs.getObjectAt(i1));
					out.printf("%sOtherCertID: %s%n", indentString, otherCertID.toASN1Primitive().toString());
				}
			} else if (attr.getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_revocationRefs)) {
				ASN1Sequence completeRevocationRefs = (ASN1Sequence) attr.getAttrValues().getObjectAt(0);
				for (int i1 = 0; i1 < completeRevocationRefs.size(); i1++) {
					CrlOcspRef crlOcspRef = CrlOcspRef.getInstance(completeRevocationRefs.getObjectAt(i1));
					final CrlListID crlids = crlOcspRef.getCrlids();
					final OcspListID ocspids = crlOcspRef.getOcspids();
					out.printf("%sCrlOcspRef: %d CRLValidatedID(s), %d OcspResponsesID(s)%n", indentString, crlids != null ? crlids.getCrls().length : 0,
						  ocspids != null ? ocspids.getOcspResponses().length : 0);
					if (crlids != null) {
						for (CrlValidatedID crlValidatedID : crlids.getCrls()) {
							out.printf("%s - CrlValidatedID: %s%s%n", indentString, DSSASN1Utils.getDEREncoded(crlValidatedID.getCrlHash()).toString(),
								  (crlValidatedID.getCrlIdentifier() != null) ? ", issued by: " + crlValidatedID.getCrlIdentifier().getCrlIssuer()
										.toString() + " on " + crlValidatedID.getCrlIdentifier().getCrlIssuedTime().getDate().toString() : "");
						}
					}
					if (ocspids != null) {
						for (OcspResponsesID ocspResponsesID : ocspids.getOcspResponses()) {
							final OtherHash ocspRepHash = ocspResponsesID.getOcspRepHash();
							final String string = ocspRepHash == null ? "NULL ocsp resp. hash!" : ocspRepHash.getEncoded().toString();
							out.printf("%S - OcspResponsesID: %s%s%n", indentString, string, (ocspResponsesID.getOcspIdentifier() != null) ? ", responded by: " + String
								  .valueOf(ocspResponsesID.getOcspIdentifier().getOcspResponderID().getName()) + " on " + String
								  .valueOf(ocspResponsesID.getOcspIdentifier().getProducedAt().getDate()) : "");
						}
					}
				}
			} else if (attr.getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_certValues)) {
				ASN1Sequence certValues = (ASN1Sequence) attr.getAttrValues().getObjectAt(0);
				out.printf("%sCertificateValues: %d certificate(s)%n", indentString, certValues.size());
				for (int i1 = 0; i1 < certValues.size(); i1++) {
					Certificate c = Certificate.getInstance(certValues.getObjectAt(i1));
					final int dssId = 1;//CertificateIdentifier.getId(DSSUtils.loadCertificate(c.getEncoded()));
					out.printf("%s - Certificate: DSS[%s] / SN: %s / Issued by: %s / SN: %s%n", indentString, dssId, c.getSubject(), c.getIssuer(), c.getSerialNumber());
				}
			} else if (attr.getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_revocationValues)) {
				RevocationValues revValues = RevocationValues.getInstance(attr.getAttrValues().getObjectAt(0));
				out.printf("%SRevocationValues: %d CRL(s), %d OCSP response(s)%n", indentString, revValues.getCrlVals().length, revValues.getOcspVals().length);
				for (CertificateList crlHolder : revValues.getCrlVals()) {

					final int length = crlHolder.getRevokedCertificates().length;
					final X500Name issuer = crlHolder.getIssuer();
					final String dateString = DSSUtils.formatInternal(crlHolder.getThisUpdate().getDate());
					out.printf("%s - CertificateList (CRL): %d entries / Issued by: %s on %s%n", indentString, length, issuer, dateString);
				}
				for (BasicOCSPResponse ocspHolder : revValues.getOcspVals()) {
					out.printf("%S - BasicOCSPResponse: %d response(s), responder: %s on %s%n", indentString, ocspHolder.getTbsResponseData().getResponses().size(),
						  String.valueOf(ocspHolder.getTbsResponseData().getResponderID().getName()), String.valueOf(ocspHolder.getTbsResponseData().getProducedAt().getDate()));
				}
			} else if (attr.getAttrType().getId().equals(OID.id_aa_ATSHashIndex.getId())) {
				ASN1Sequence atsHashIndex = (ASN1Sequence) attr.getAttrValues().getObjectAt(0);
				int i = 0;
				if (atsHashIndex.size() == 4) {
					if (atsHashIndex.getObjectAt(i) instanceof ASN1Sequence) {
						AlgorithmIdentifier algoIdentifier = AlgorithmIdentifier.getInstance((ASN1Sequence) atsHashIndex.getObjectAt(0));
						out.printf("%s - Algorithm Identifier: %s%n", indentString, helperResolvePKCSIdentifier(algoIdentifier.getAlgorithm().getId()));
					} else {
						ASN1ObjectIdentifier algorithmIdentifier = (ASN1ObjectIdentifier) atsHashIndex.getObjectAt(0);
						out.printf("%s - Algorithm Identifier: %s%n", indentString, helperResolvePKCSIdentifier(algorithmIdentifier.getId()));
					}
					i++;
				}
				ASN1Sequence certificatesHashIndex = (ASN1Sequence) atsHashIndex.getObjectAt(i);
				i++;
				out.printf("%s - certificatesHashIndex size: %d%n", indentString, certificatesHashIndex.size());
				ASN1Sequence crLsHashIndex = (ASN1Sequence) atsHashIndex.getObjectAt(i);
				i++;
				out.printf("%s - crLsHashIndex size: %d%n", indentString, crLsHashIndex.size());
				ASN1Sequence unsignedAttributesHashIndex = (ASN1Sequence) atsHashIndex.getObjectAt(i);
				i++;
				out.printf("%s - unsignedAttributesHashIndex size: %d%n", indentString, unsignedAttributesHashIndex.size());
			} else if (attr.getAttrType().getId().equals("1.2.840.113549.1.9.6")) {
				ASN1Sequence countersignatureAttributes = (ASN1Sequence) attr.getAttrValues().getObjectAt(0);
				out.printf("%sVersion: %s", indentString, countersignatureAttributes.getObjectAt(0));

				SignerInfo signerInfo = SignerInfo.getInstance(countersignatureAttributes);
				ASN1Set authenticatedAttributes = signerInfo.getAuthenticatedAttributes();

				for (int i = 1; i < countersignatureAttributes.size(); ++i) {
					out.printf("\n%sAttribute: %s %s", indentString, i, countersignatureAttributes.getObjectAt(i));
				}
			} else {
				out.printf("%SValue:%s%n", indentString, attr.getAttrValues().toString());
			}
		}
	}

	/**
	 * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The returned
	 * String will be double the length of the passed array, as it takes two characters to represent any given byte.
	 *
	 * @param data a byte[] to convert to Hex characters
	 * @return A String containing hexadecimal characters
	 */
	public static String encodeHexString(final byte[] data) {
		return new String(encodeHex(data));
	}

	/**
	 * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The maximum length of the returned
	 * String is limited by {@code maxLength} parameter.
	 *
	 * @param data      a byte[] to convert to Hex characters
	 * @param maxLength the maximum length of the returned string
	 * @return A String containing hexadecimal characters
	 */
	public static String encodeHexString(final byte[] data, int maxLength) {

		byte[] data_ = data.length > maxLength ? Arrays.copyOf(data, maxLength) : data;
		final String encoded = new String(encodeHex(data_)) + (data.length > maxLength ? "...(" + (data.length - maxLength) + " more)" : "");
		return encoded;

	}

	/**
	 * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
	 * The returned array will be double the length of the passed array, as it takes two characters to represent any
	 * given byte.
	 *
	 * @param data a byte[] to convert to Hex characters
	 * @return A char[] containing hexadecimal characters
	 */
	public static char[] encodeHex(byte[] data) {
		return encodeHex(data, true);
	}

	/**
	 * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
	 * The returned array will be double the length of the passed array, as it takes two characters to represent any
	 * given byte.
	 *
	 * @param data        a byte[] to convert to Hex characters
	 * @param toLowerCase <code>true</code> converts to lowercase, <code>false</code> to uppercase
	 * @return A char[] containing hexadecimal characters
	 * @since 1.4
	 */
	public static char[] encodeHex(byte[] data, boolean toLowerCase) {
		return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
	}

	/**
	 * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
	 * The returned array will be double the length of the passed array, as it takes two characters to represent any
	 * given byte.
	 *
	 * @param data     a byte[] to convert to Hex characters
	 * @param toDigits the output alphabet
	 * @return A char[] containing hexadecimal characters
	 * @since 1.4
	 */
	protected static char[] encodeHex(byte[] data, char[] toDigits) {
		int l = data.length;
		char[] out = new char[l << 1];
		// two characters form the hex value.
		for (int i = 0, j = 0; i < l; i++) {
			out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
			out[j++] = toDigits[0x0F & data[i]];
		}
		return out;
	}

	/**
	 * <p>Repeat a String {@code repeat} times to form a
	 * new String.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.repeat(null, 2) = null
	 * DSSUtils.repeat("", 0)   = ""
	 * DSSUtils.repeat("", 2)   = ""
	 * DSSUtils.repeat("a", 3)  = "aaa"
	 * DSSUtils.repeat("ab", 2) = "abab"
	 * DSSUtils.repeat("a", -2) = ""
	 * </pre>
	 *
	 * @param str    the String to repeat, may be null
	 * @param repeat number of times to repeat str, negative treated as zero
	 * @return a new String consisting of the original String repeated,
	 * {@code null} if null String input
	 */
	public static String repeat(String str, int repeat) {
		// Performance tuned for 2.0 (JDK1.4)

		if (str == null) {
			return null;
		}
		if (repeat <= 0) {
			return EMPTY;
		}
		int inputLength = str.length();
		if (repeat == 1 || inputLength == 0) {
			return str;
		}
		if (inputLength == 1 && repeat <= PAD_LIMIT) {
			return padding(repeat, str.charAt(0));
		}

		int outputLength = inputLength * repeat;
		switch (inputLength) {
			case 1:
				char ch = str.charAt(0);
				char[] output1 = new char[outputLength];
				for (int i = repeat - 1; i >= 0; i--) {
					output1[i] = ch;
				}
				return new String(output1);
			case 2:
				char ch0 = str.charAt(0);
				char ch1 = str.charAt(1);
				char[] output2 = new char[outputLength];
				for (int i = repeat * 2 - 2; i >= 0; i--, i--) {
					output2[i] = ch0;
					output2[i + 1] = ch1;
				}
				return new String(output2);
			default:
				StringBuilder buf = new StringBuilder(outputLength);
				for (int i = 0; i < repeat; i++) {
					buf.append(str);
				}
				return buf.toString();
		}
	}

	/**
	 * <p>Returns padding using the specified delimiter repeated
	 * to a given length.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.padding(0, 'e')  = ""
	 * DSSUtils.padding(3, 'e')  = "eee"
	 * DSSUtils.padding(-2, 'e') = IndexOutOfBoundsException
	 * </pre>
	 * <p/>
	 * <p>Note: this method doesn't not support padding with
	 * <a href="http://www.unicode.org/glossary/#supplementary_character">Unicode Supplementary Characters</a>
	 * as they require a pair of {@code char}s to be represented.
	 * If you are needing to support full I18N of your applications
	 * consider using {@link #repeat(String, int)} instead.
	 * </p>
	 *
	 * @param repeat  number of times to repeat delim
	 * @param padChar character to repeat
	 * @return String with repeated character
	 * @throws DSSException if {@code repeat &lt; 0}
	 * @see #repeat(String, int)
	 */
	private static String padding(int repeat, char padChar) throws DSSException {
		if (repeat < 0) {
			throw new DSSException("Cannot pad a negative amount: " + repeat);
		}
		final char[] buf = new char[repeat];
		for (int i = 0; i < buf.length; i++) {
			buf[i] = padChar;
		}
		return new String(buf);
	}
}
