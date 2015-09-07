import java.io.File;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class MyTest {

	public static void main(String[] args) {
		System.out.println("Hello!");


		File signatureFileToValidate = new File("C:\\git\\dss4.5RC2\\my-test\\src\\main\\resources\\Examples\\Feature_5204_valid_signed_projectteam_qes_xml.xml");
		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		CertificateVerifier validationSources = new CommonCertificateVerifier();

		validationSources.setCrlSource(new OnlineCRLSource());
		validationSources.setOcspSource(new OnlineOCSPSource());

		NDesignTrustedListsCertificateSource tslSource = new NDesignTrustedListsCertificateSource();
		tslSource.setCheckSignature(false);

		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL_LU_9_ab20052015.xml", null);


		validationSources.setTrustedCertSource(tslSource);

		validator.setCertificateVerifier(validationSources);

		final Reports reports = validator.validateDocument();
		reports.print();

	}
}
