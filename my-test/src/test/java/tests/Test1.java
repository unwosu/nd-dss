package tests;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class Test1 {

	public static void main(String[] args) {

		File tslSigningCertificateFile = new File("C:\\git\\dss4.5RC2\\my-test\\src\\main\\resources\\Examples\\tsl.crt");
		final CertificateToken tslSigningCertificateToken = DSSUtils.loadCertificate(tslSigningCertificateFile);


		File signatureFileToValidate = new File("C:\\git\\dss4.5RC2\\my-test\\src\\main\\resources\\testdata\\TIP1-A_5447_TF_09_SignedEGES.xml");

		DSSDocument signatureToValidate = new FileDocument(signatureFileToValidate);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureToValidate);
		CertificateVerifier validationSources = new CommonCertificateVerifier();

		validationSources.setCrlSource(new OnlineCRLSource());
		validationSources.setOcspSource(new OnlineOCSPSource());

		NDesignTrustedListsCertificateSource tslSource = new NDesignTrustedListsCertificateSource();
		tslSource.setCheckSignature(false);

		List<CertificateToken> signingCertificateList = new ArrayList<CertificateToken>();
		signingCertificateList.add(tslSigningCertificateToken);
		//		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL_LU_9_ab20052015.xml", signingCertificateList);
		//		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL_LU_9_ab20052015-critical-removed.xml", signingCertificateList);
		//		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL_RU_20150623_441.xml", signingCertificateList);
		tslSource.loadTSL("file:///C:/git/dss4.5RC2/my-test/src/main/resources/Examples/TSL-testref_469.xml", signingCertificateList);


		validationSources.setTrustedCertSource(tslSource);

		validator.setCertificateVerifier(validationSources);

		final Reports reports = validator.validateDocument();
		reports.print();

	}
}
