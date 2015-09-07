import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class NDesignTrustedListsCertificateSource extends TrustedListsCertificateSource {

	private static final Logger logger = LoggerFactory.getLogger(NDesignTrustedListsCertificateSource.class);


	public NDesignTrustedListsCertificateSource() {

		dataLoader = new CommonsDataLoader();
	}

	protected void loadTSL(final String url, final List<CertificateToken> signingCertList) {

		diagnosticInfo.clear();
		super.loadTSL(url, "N-DESIGN", signingCertList);
		logger.info("Loading completed: {} certificates", certPool.getNumberOfCertificates());
	}
}




