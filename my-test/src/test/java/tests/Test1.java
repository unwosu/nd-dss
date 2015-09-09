package tests;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;

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
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class Test1 {

	private static CertificateToken tslSigningCertificateToken;

	static {

		File tslSigningCertificateFile = new File("src\\main\\resources\\Examples\\tsl.crt");
		tslSigningCertificateToken = DSSUtils.loadCertificate(tslSigningCertificateFile);
	}

	private static CertificateVerifier validationSources = null;

	@Test
	public void test_4624_TF_02_default_signed_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\4624_TF_02_default_signed.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();
	}

	@Test
	public void test_envelopedSignedChildDesRoot_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\envelopedSignedChildDesRoot.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();

	}

	@Test
	@Ignore
	public void test_Feature_5000_SignDoc_PDF_A_nonQES_with_xTV_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\Feature_5000_SignDoc_PDF_A_nonQES_with_xTV.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		File policyFile = new File("src\\main\\resources\\policy\\constraint-non-qualified.xml");
		Reports reports = validator.validateDocument(policyFile);
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		String signatureId = getFirstSignatureId(simpleReport);
		String indication = simpleReport.getIndication(signatureId);

		assert Indication.INDETERMINATE.equals(indication);
		final String subIndication = simpleReport.getSubIndication(signatureId);
		assert SubIndication.NO_CERTIFICATE_CHAIN_FOUND.equals(subIndication);

		reports = validator.validateDocument();
		//		reports.print();
		simpleReport = reports.getSimpleReport();
		signatureId = getFirstSignatureId(simpleReport);
		indication = simpleReport.getIndication(signatureId);

		assert Indication.VALID.equals(indication);
	}

	@Test
	@Ignore
	public void test_Feature_5000_SignDoc_PDF_A_QES_with_xTV_HBA_signed_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\Feature_5000_SignDoc_PDF_A_QES_with_xTV_HBA_signed.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();

	}

	@Test
	@Ignore
	public void test_PDF_A_vier_seiten_signed_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\PDF_A_vier_seiten_signed.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();

		final SimpleReport simpleReport = reports.getSimpleReport();
		final String signatureId = getFirstSignatureId(simpleReport);
		final String indication = simpleReport.getIndication(signatureId);

		assert Indication.VALID.equals(indication);

		final String signatureFormat = simpleReport.getSignatureFormat(signatureId);
		assert SignatureLevel.PAdES_BASELINE_B.name().equals(signatureFormat);

	}

	private String getFirstSignatureId(SimpleReport simpleReport) {
		final List<String> signatureIdList = simpleReport.getSignatureIdList();
		return signatureIdList.get(0);
	}

	@Test
	public void test_TIP1_A_5447_TF_05_SignedEGES_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\TIP1-A_5447_TF_05_SignedEGES.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();
	}

	@Test
	public void test_TIP1_A_5447_TF_09_SignedEGES_xml() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\TIP1-A_5447_TF_09_SignedEGES.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();
	}

	@Test
	public void test_TIP1_A_5447_TF_25_nonQES_Signed_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\TIP1-A_5447_TF_25_nonQES_Signed.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();
	}

	@Test
	public void test_TIP1_A_5447_TF_27_QES_Signed_pdf() {

		File signatureFileToValidate = new File("src\\main\\resources\\testdata\\TIP1-A_5447_TF_27_QES_Signed.pdf");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		validator.setCertificateVerifier(getValidationSources(tslSigningCertificateToken));

		final Reports reports = validator.validateDocument();
		reports.print();
	}

	private static CertificateVerifier getValidationSources(CertificateToken tslSigningCertificateToken) {

		if (validationSources != null) {
			return validationSources;
		}
		validationSources = new CommonCertificateVerifier();
		validationSources.setCrlSource(new OnlineCRLSource());
		validationSources.setOcspSource(new OnlineOCSPSource());

		NDesignTrustedListsCertificateSource tslSource = new NDesignTrustedListsCertificateSource();
		tslSource.setCheckSignature(false);
		tslSource.setDataLoader(new FileDataLoader());

		List<CertificateToken> signingCertificateList = new ArrayList<CertificateToken>();
		signingCertificateList.add(tslSigningCertificateToken);
		//		tslSource.loadTSL("src/main/resources/Examples/TSL_LU_9_ab20052015.xml", signingCertificateList);
		tslSource.loadTSL("src/main/resources/Examples/TSL_LU_9_ab20052015-critical-removed.xml", signingCertificateList);
		tslSource.loadTSL("src/main/resources/Examples/TSL_RU_20150623_441.xml", signingCertificateList);
		tslSource.loadTSL("src/main/resources/Examples/TSL-testref_469.xml", signingCertificateList);


		validationSources.setTrustedCertSource(tslSource);
		return validationSources;
	}
}
