package eu.europa.esig.dss.tsl;

import java.io.File;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class NDesignTrustedListsCertificateSource extends TrustedListsCertificateSource {

	private static final Logger logger = LoggerFactory.getLogger(NDesignTrustedListsCertificateSource.class);

	private String tslPath;

	static {

		System.out.println("------------> #NDesignTrustedListsCertificateSource# $");
	}

	public NDesignTrustedListsCertificateSource() {

		System.out.println("------------> #NDesignTrustedListsCertificateSource# +");
		dataLoader = new CommonsDataLoader();
	}

	public String getTslPath() {
		return tslPath;
	}

	public void setTslPath(String tslPath) {

		File file = new File("");
		System.out.println("#####################" + file.getAbsolutePath());
		System.out.println("------------> #NDesignTrustedListsCertificateSource#setTslPath #" + tslPath);
		this.tslPath = tslPath;

		loadTsl(tslPath, null);
	}

	public void loadTsl(final String url, final List<CertificateToken> signingCertList) {

		System.out.println("------------> #NDesignTrustedListsCertificateSource#loadTsl #");
		super.loadTSL(url, "N-DESIGN", signingCertList);
		logger.info("Loading completed: {} certificates", certPool.getNumberOfCertificates());
	}
}




