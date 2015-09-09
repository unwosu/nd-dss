package tests.signeddocs;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.FullSignatureScope;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.xades.validation.XmlElementSignatureScope;
import eu.europa.esig.dss.xades.validation.XmlRootSignatureScope;
import tests.CAdESHelper;
import tests.FileDataLoader;
import tests.NDesignTrustedListsCertificateSource;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class Test {

	private static CertificateToken tslSigningCertificateToken;

	static File nQESXmlPolicyFile = new File("src\\main\\resources\\policy\\policy-nonQES-xml.xml");
	static File nQESCmsPolicyFile = new File("src\\main\\resources\\policy\\policy-nonQES-cms.xml");
	static File nQESPdfPolicyFile = new File("src\\main\\resources\\policy\\policy-nonQES-pdf.xml");
	static File nQESSMimePolicyFile = new File("src\\main\\resources\\policy\\policy-nonQES-smime.xml");

	static File qesXmlPolicyFile = new File("src\\main\\resources\\policy\\policy-QES-xml.xml");
	static File qesPdfPolicyFile = new File("src\\main\\resources\\policy\\policy-QES-pdf.xml");
	static File qesCmsPolicyFile = new File("src\\main\\resources\\policy\\policy-QES-cms.xml");

	static List<DSSDocument> detachedDocument = new ArrayList<DSSDocument>();

	static {

		File tslSigningCertificateFile = new File("src\\main\\resources\\Examples\\TSL-testref_469.crt");
		tslSigningCertificateToken = DSSUtils.loadCertificate(tslSigningCertificateFile);


		File detachedFile = new File("src\\main\\resources\\signed-docs\\unsigned.tiff");
		DSSDocument detachedContent = new FileDocument(detachedFile);
		detachedDocument.add(detachedContent);
	}

	private static CertificateVerifier validationSources = null;

	@org.junit.Test
	public void test_nonQES_detached_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_detached.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(nQESXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);


		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlElementSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_detached_tiff_signature_p7s() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_detached_tiff_signature.p7s");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		validator.setDetachedContents(detachedDocument);

		final Reports reports = validator.validateDocument(nQESCmsPolicyFile);
		reports.print();

		//		CAdESHelper.dumpCMSSignedDocument(signatureToValidate);

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.CAdES_BASELINE_B);

		assertSignatureScope(signatureId, simpleReport, FullSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_enveloped_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloped.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		validator.setDetachedContents(detachedDocument);

		final Reports reports = validator.validateDocument(nQESPdfPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.PAdES_BASELINE_B);

		assertSignatureScope(signatureId, simpleReport, FullSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_enveloped_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloped.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(nQESXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlRootSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_enveloped_CDA_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloped_CDA.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(nQESXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert "urn:gematik:fa:sak:cda:r1:v1".equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlRootSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_enveloping_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloping.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(nQESXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlElementSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_enveloping_CDA_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloping_CDA.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(nQESXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert "urn:gematik:fa:sak:cda:r1:v1".equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlElementSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_enveloping_smime_txt() throws MessagingException, IOException, CMSException, SMIMEException {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloping_smime.txt");
		final InputStream inputStream = DSSUtils.toInputStream(signatureFileToValidate);

		DSSDocument signatureToValidate = getDssDocumentFromSMime(inputStream);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		validator.setDetachedContents(detachedDocument);

		final Reports reports = validator.validateDocument(nQESSMimePolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.CAdES_BASELINE_B);

		assertSignatureScope(signatureId, simpleReport, FullSignatureScope.class);
	}

	@org.junit.Test
	public void test_nonQES_enveloping_tiff_p7s() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloping_tiff.p7s");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		validator.setDetachedContents(detachedDocument);

		final Reports reports = validator.validateDocument(nQESCmsPolicyFile);
		reports.print();

		//		CAdESHelper.dumpCMSSignedDocument(signatureToValidate);

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.CAdES_BASELINE_B);

		assertSignatureScope(signatureId, simpleReport, FullSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_detached_tiff_signature_p7s() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_detached_tiff_signature.p7s");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		validator.setDetachedContents(detachedDocument);

		final Reports reports = validator.validateDocument(qesCmsPolicyFile);
		reports.print();

		//		CAdESHelper.dumpCMSSignedDocument(signatureToValidate);

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.CAdES_BASELINE_B);

		assertSignatureScope(signatureId, simpleReport, FullSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_enveloped_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_enveloped.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		validator.setDetachedContents(detachedDocument);

		final Reports reports = validator.validateDocument(qesPdfPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.PAdES_BASELINE_B);

		assertSignatureScope(signatureId, simpleReport, FullSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_enveloped_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_enveloped.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(qesXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlRootSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_enveloped_CDA_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_enveloped_CDA.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(qesXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert "urn:gematik:fa:sak:cda:r1:v1".equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlRootSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_enveloped_EGES_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_enveloped_EGES.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(qesXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert "urn:gematik:fa:sak:eges:r1:v1".equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlRootSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_enveloping_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_enveloping.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(qesXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlElementSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_enveloping_CDA_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_enveloping_CDA.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument(qesXmlPolicyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.XAdES_BASELINE_B);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertSignedInfoC14NMethod(diagnosticData, signatureId);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert "urn:gematik:fa:sak:cda:r1:v1".equals(policyId);

		assertSignatureScope(signatureId, simpleReport, XmlElementSignatureScope.class);
	}

	@org.junit.Test
	public void test_QES_enveloping_tiff_p7s() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\QES_enveloping_tiff.p7s");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		validator.setDetachedContents(detachedDocument);

		final Reports reports = validator.validateDocument(qesCmsPolicyFile);
		reports.print();

		CAdESHelper.dumpCMSSignedDocument(signatureToValidate);

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);

		assertIsValid(simpleReport, signatureId);

		assertSignatureFormat(simpleReport, signatureId, SignatureLevel.CAdES_BASELINE_B);

		assertSignatureScope(signatureId, simpleReport, FullSignatureScope.class);
	}

	private DSSDocument getDssDocumentFromSMime(InputStream inputStream) throws MessagingException, CMSException, SMIMEException, IOException {

		Properties props = System.getProperties();
		Session session = Session.getDefaultInstance(props, null);
		MimeMessage mimeMessage = new MimeMessage(session, inputStream);

		SMIMESigned smimeSigned = new SMIMESigned(mimeMessage);
		MimeBodyPart content = smimeSigned.getContent();
		System.out.println("Content:");
		Object cont = content.getContent();
		if (cont instanceof String) {
			System.out.println((String) cont);
		}
		final InputStream rawInputStream = ((MimeMessage) smimeSigned.getContentWithSignature()).getRawInputStream();
		final byte[] bytes2 = DSSUtils.toByteArray(rawInputStream);

		final byte[] decodeBase64 = Base64.decodeBase64(bytes2);

		return new InMemoryDocument(decodeBase64);
	}

	private String getFirstSignatureId(SimpleReport simpleReport) {
		final List<String> signatureIdList = simpleReport.getSignatureIdList();
		return signatureIdList.get(0);
	}

	private static CertificateVerifier getValidationSources(CertificateToken tslSigningCertificateToken) {

		if (validationSources != null) {
			return validationSources;
		}
		validationSources = new CommonCertificateVerifier();
		validationSources.setCrlSource(new OnlineCRLSource());
		validationSources.setOcspSource(new OnlineOCSPSource());

		NDesignTrustedListsCertificateSource tslSource = new NDesignTrustedListsCertificateSource();
		//		tslSource.setCheckSignature(false);
		tslSource.setDataLoader(new FileDataLoader());

		List<CertificateToken> signingCertificateList = new ArrayList<CertificateToken>();
		signingCertificateList.add(tslSigningCertificateToken);
		//		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL_LU_9_ab20052015.xml", signingCertificateList);
		//		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL_LU_9_ab20052015-critical-removed.xml", signingCertificateList);
		//		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL_RU_20150623_441.xml", signingCertificateList);
		tslSource.loadTSL("src/main/resources/Examples/TSL-testref_469.xml", signingCertificateList);


		validationSources.setTrustedCertSource(tslSource);
		return validationSources;
	}

	private void assertIsValid(SimpleReport simpleReport, String signatureId) {

		final String indication = simpleReport.getIndication(signatureId);
		assert Indication.VALID.equals(indication);
	}

	private void assertSignedInfoC14NMethod(DiagnosticData diagnosticData, String signatureId) {
		String signedInfoC14NMethod = diagnosticData.getSignedInfoC14NMethod(signatureId);
		assert CanonicalizationMethod.EXCLUSIVE.equals(signedInfoC14NMethod);
	}

	private void assertSignatureFormat(SimpleReport simpleReport, String signatureId, SignatureLevel signatureLevel) {
		final String signatureFormat = simpleReport.getSignatureFormat(signatureId);
		assert signatureLevel.name().equals(signatureFormat);
	}

	private void assertSignatureScope(String signatureId, SimpleReport simpleReport, Class<?> signatureScopeClass) {

		final List<String> signatureScopeList = simpleReport.getSignatureScope(signatureId);
		assert signatureScopeList.size() == 1;
		final String signatureScope = signatureScopeList.get(0);
		assert signatureScopeClass.getSimpleName().equals(signatureScope);
	}
}
