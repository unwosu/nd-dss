package tests.signeddocs;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
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
import tests.FileDataLoader;
import tests.NDesignTrustedListsCertificateSource;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class Test {

	private static CertificateToken tslSigningCertificateToken;

	static {

		File tslSigningCertificateFile = new File("src\\main\\resources\\Examples\\TSL-testref_469.crt");
		tslSigningCertificateToken = DSSUtils.loadCertificate(tslSigningCertificateFile);
	}

	@org.junit.Test
	public void test_nonQES_detached_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_detached.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);
		String indication = simpleReport.getIndication(signatureId);

		assert Indication.VALID.equals(indication);

		final String signatureFormat = simpleReport.getSignatureFormat(signatureId);
		assert SignatureLevel.XAdES_BASELINE_B.name().equals(signatureFormat);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		String signedInfoC14NMethod = diagnosticData.getSignedInfoC14NMethod(signatureId);
		assert CanonicalizationMethod.EXCLUSIVE.equals(signedInfoC14NMethod);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		List<String> signatureScopeList = simpleReport.getSignatureScope(signatureId);
		assert signatureScopeList.size() == 1;
		final String signatureScope = signatureScopeList.get(0);
		assert XmlElementSignatureScope.class.getSimpleName().equals(signatureScope);

	}

	@org.junit.Test
	public void test_nonQES_enveloped_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloped.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		File policyFile = new File("src\\main\\resources\\policy\\policy-nonQES-enveloped.xml");
		final Reports reports = validator.validateDocument(policyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);
		String indication = simpleReport.getIndication(signatureId);

		assert Indication.VALID.equals(indication);

		final String signatureFormat = simpleReport.getSignatureFormat(signatureId);
		assert SignatureLevel.XAdES_BASELINE_B.name().equals(signatureFormat);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		String signedInfoC14NMethod = diagnosticData.getSignedInfoC14NMethod(signatureId);
		assert CanonicalizationMethod.EXCLUSIVE.equals(signedInfoC14NMethod);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		List<String> signatureScopeList = simpleReport.getSignatureScope(signatureId);
		assert signatureScopeList.size() == 1;
		final String signatureScope = signatureScopeList.get(0);
		assert XmlRootSignatureScope.class.getSimpleName().equals(signatureScope);
	}

	@org.junit.Test
	public void test_nonQES_enveloping_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_enveloping.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		File policyFile = new File("src\\main\\resources\\policy\\policy-nonQES-enveloped-xml.xml");
		final Reports reports = validator.validateDocument(policyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);
		String indication = simpleReport.getIndication(signatureId);

		assert Indication.VALID.equals(indication);

		final String signatureFormat = simpleReport.getSignatureFormat(signatureId);
		assert SignatureLevel.XAdES_BASELINE_B.name().equals(signatureFormat);

		final DiagnosticData diagnosticData = reports.getDiagnosticData();

		String signedInfoC14NMethod = diagnosticData.getSignedInfoC14NMethod(signatureId);
		assert CanonicalizationMethod.EXCLUSIVE.equals(signedInfoC14NMethod);

		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		List<String> signatureScopeList = simpleReport.getSignatureScope(signatureId);
		assert signatureScopeList.size() == 1;
		final String signatureScope = signatureScopeList.get(0);
		assert XmlElementSignatureScope.class.getSimpleName().equals(signatureScope);
	}

	@org.junit.Test
	public void test_nonQES_detached_tiff_signature_p7s() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_detached_tiff_signature.p7s");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		List<DSSDocument> detachedContentList = new ArrayList<DSSDocument>();
		File detachedFile = new File("src\\main\\resources\\signed-docs\\unsigned.tiff");
		DSSDocument detachedContent = new FileDocument(detachedFile);
		detachedContentList.add(detachedContent);
		validator.setDetachedContents(detachedContentList);

		File policyFile = new File("src\\main\\resources\\policy\\policy-nonQES-enveloped-cms.xml");
		final Reports reports = validator.validateDocument(policyFile);
		reports.print();

//		CAdESHelper.dumpCMSSignedDocument(signatureToValidate);

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);
		String indication = simpleReport.getIndication(signatureId);

		assert Indication.VALID.equals(indication);

		final String signatureFormat = simpleReport.getSignatureFormat(signatureId);
		assert SignatureLevel.CAdES_BASELINE_B.name().equals(signatureFormat);

		List<String> signatureScopeList = simpleReport.getSignatureScope(signatureId);
		assert signatureScopeList.size() == 1;
		final String signatureScope = signatureScopeList.get(0);
		assert FullSignatureScope.class.getSimpleName().equals(signatureScope);

//		final DiagnosticData diagnosticData = reports.getDiagnosticData();
//		diagnosticData.getCo

	}

	@org.junit.Test
	public void test_xxx() {

		File signatureFileToValidate = new File("src\\main\\resources\\signed-docs\\nonQES_detached_tiff_signature.p7s");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		List<DSSDocument> detachedContentList = new ArrayList<DSSDocument>();
		File detachedFile = new File("src\\main\\resources\\signed-docs\\unsigned.tiff");
		DSSDocument detachedContent = new FileDocument(detachedFile);
		detachedContentList.add(detachedContent);
		validator.setDetachedContents(detachedContentList);

		File policyFile = new File("src\\main\\resources\\policy\\policy-nonQES-enveloped.xml");
		final Reports reports = validator.validateDocument(policyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);
		String indication = simpleReport.getIndication(signatureId);

		assert Indication.VALID.equals(indication);

		final String signatureFormat = simpleReport.getSignatureFormat(signatureId);
		assert SignatureLevel.CAdES_BASELINE_B.name().equals(signatureFormat);

		List<String> signatureScopeList = simpleReport.getSignatureScope(signatureId);
		assert signatureScopeList.size() == 1;
		final String signatureScope = signatureScopeList.get(0);
		assert FullSignatureScope.class.getSimpleName().equals(signatureScope);
	}

	private String getFirstSignatureId(SimpleReport simpleReport) {
		final List<String> signatureIdList = simpleReport.getSignatureIdList();
		return signatureIdList.get(0);
	}

	private static CertificateVerifier getValidationSources(CertificateToken tslSigningCertificateToken) {

		CertificateVerifier validationSources = new CommonCertificateVerifier();

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
}
