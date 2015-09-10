package tests.validation;

import java.io.File;
import java.io.InputStream;

import org.junit.Test;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.wsclient.validation.DSSException_Exception;
import eu.europa.esig.dss.wsclient.validation.ObjectFactory;
import eu.europa.esig.dss.wsclient.validation.ValidationService;
import eu.europa.esig.dss.wsclient.validation.ValidationService_Service;
import eu.europa.esig.dss.wsclient.validation.WsDocument;
import eu.europa.esig.dss.wsclient.validation.WsValidationReport;

/**
 *
 */
public class WsValidation {

	private static ObjectFactory FACTORY;

	static {

		System.setProperty("javax.xml.bind.JAXBContext", "com.sun.xml.internal.bind.v2.ContextFactory");
		FACTORY = new ObjectFactory();

	}

	/**
	 * Validate the document with the 102853 validation policy
	 *
	 * @throws DSSException
	 */
	@Test
	public void validateDocument() throws DSSException {


		final File signedFile = new File("src\\main\\resources\\signed-docs\\nonQES_detached.xml");
		final WsDocument wsSignedDocument = toWsDocument(signedFile);

		//		final File detachedFile = new File("detached-file");
		//		final WsDocument wsDetachedDocument = detachedFile != null ? toWsDocument(detachedFile) : null;
		final WsDocument wsDetachedDocument = null;

		final File policyFile = new File("src\\main\\resources\\policy\\policy-nonQES-xml.xml");
		final InputStream inputStream = DSSUtils.toInputStream(policyFile);
		final WsDocument wsPolicyDocument = new WsDocument();
		wsPolicyDocument.setBytes(DSSUtils.toByteArray(inputStream));

		//assertValidationPolicyFileValid(validationPolicyURL);

		ValidationService_Service.setROOT_SERVICE_URL("http://localhost:8080/wservice");
		final ValidationService_Service validationService_service = new ValidationService_Service();
		final ValidationService validationServiceImplPort = validationService_service.getValidationServiceImplPort();
		final WsValidationReport wsValidationReport;
		try {
			wsValidationReport = validationServiceImplPort.validateDocument(wsSignedDocument, wsDetachedDocument, wsPolicyDocument, true);
		} catch (DSSException_Exception e) {
			throw new DSSException(e);
		} catch (Throwable e) {
			e.printStackTrace();
			throw new DSSException(e);
		}

		String xmlData = "";
		try {

			// In case of some signatures, the returned data are not UTF-8 encoded. The conversion is forced.

			String xmlDiagnosticData = wsValidationReport.getXmlDiagnosticData();
			System.out.println();
			System.out.println(xmlDiagnosticData);
			System.out.println();
			xmlData = xmlDiagnosticData;
			String xmlDetailedReport = wsValidationReport.getXmlDetailedReport();
			System.out.println(xmlDetailedReport);
			System.out.println();
			xmlData = xmlDetailedReport;
			String xmlSimpleReport = wsValidationReport.getXmlSimpleReport();
			System.out.println(xmlSimpleReport);
			xmlData = xmlSimpleReport;
		} catch (Exception e) {

			final String base64Encode = DSSUtils.base64Encode(new InMemoryDocument(xmlData.getBytes()));
			System.out.println("Erroneous data: " + base64Encode);
			if (e instanceof DSSException) {
				throw (DSSException) e;
			}
			throw new DSSException(e);
		}
	}

	private WsDocument toWsDocument(final File detachedFile) {

		final FileDocument dssDocument = new FileDocument(detachedFile);

		final WsDocument wsDocument = new WsDocument();
		wsDocument.setBytes(dssDocument.getBytes());
		wsDocument.setName(dssDocument.getName());
		wsDocument.setAbsolutePath(dssDocument.getAbsolutePath());
		final MimeType mimeType = dssDocument.getMimeType();
		final eu.europa.esig.dss.wsclient.validation.MimeType wsMimeType = FACTORY.createMimeType();
		final String mimeTypeString = mimeType.getMimeTypeString();
		wsMimeType.setMimeTypeString(mimeTypeString);
		wsDocument.setMimeType(wsMimeType);
		return wsDocument;
	}

	private XmlDom getXmlDomReport(final String report) {

		// System.out.println("############################ 2");
		final Document reportDom = DSSXMLUtils.buildDOM(report);
		return new XmlDom(reportDom);
	}
}