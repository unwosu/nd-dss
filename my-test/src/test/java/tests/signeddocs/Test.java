package tests.signeddocs;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
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
		final String policyId = diagnosticData.getPolicyId(signatureId);
		assert SignaturePolicy.IMPLICIT_POLICY.equals(policyId);

		List<String> signatureScopeList = simpleReport.getSignatureScope(signatureId);
		assert signatureScopeList.size() == 1;
		final String signatureScope = signatureScopeList.get(0);
		assert XmlElementSignatureScope.class.getSimpleName().equals(signatureScope);
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
