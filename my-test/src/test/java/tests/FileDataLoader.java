package tests;

import java.io.File;
import java.util.List;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class FileDataLoader implements DataLoader {

	@Override
	public byte[] get(String url) {

		File file = new File(url);
		final byte[] bytes = DSSUtils.toByteArray(file);
		return bytes;
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		return null;
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		return get(url);
	}

	@Override
	public byte[] post(String url, byte[] content) {
		return new byte[0];
	}

	@Override
	public void setContentType(String contentType) {

	}
}
