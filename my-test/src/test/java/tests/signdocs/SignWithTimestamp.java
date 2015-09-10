package tests.signdocs;

import java.io.IOException;
import java.net.URL;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class SignWithTimestamp {

	private static Pkcs12SignatureToken signingToken;

	@Test
	public void testSignXAdES_B() throws IOException {

		final DSSDocument toSignDocument = prepareXmlDoc();

		final DSSPrivateKeyEntry dssPrivateKeyEntry = preparePKCS12TokenAndKey();

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		parameters.setSigningCertificate(signingToken.getKeys().get(0).getCertificate());
		parameters.setCertificateChain(signingToken.getKeys().get(0).getCertificateChain());

		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(commonCertificateVerifier);
		OnlineTSPSource tspSource = new OnlineTSPSource("http://tsa.belgium.be/connect");
		tspSource.setDataLoader(new CommonsDataLoader());
		service.setTspSource(tspSource);

		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

		SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), dssPrivateKeyEntry);

		// We invoke the service to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		//DSSUtils.copy(signedDocument.openStream(), System.out);
		DSSUtils.saveToFile(signedDocument.openStream(), "target/signedXmlXadesT.xml");
	}

	/**
	 * This method converts the resource path to the absolute path.
	 *
	 * @param resourcePath
	 *            resource path
	 * @return
	 */
	public static String getPathFromResource(final String resourcePath) {

		URL uri = SignWithTimestamp.class.getResource(resourcePath);
		String absolutePath = uri.getPath();
		return absolutePath;
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static DSSDocument prepareXmlDoc() {
		String toSignFilePath = getPathFromResource("/example.xml");
		return new FileDocument(toSignFilePath);
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static DSSPrivateKeyEntry preparePKCS12TokenAndKey() {

		String pkcs12TokenFile = getPathFromResource("/user_a_rsa.p12");
		signingToken = new Pkcs12SignatureToken("password", pkcs12TokenFile);
		return signingToken.getKeys().get(0);
	}
}
