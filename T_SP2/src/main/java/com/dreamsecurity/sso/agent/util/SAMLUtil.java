package com.dreamsecurity.sso.agent.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.crypto.CryptoApiException;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.exception.SSOException;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.metadata.MetadataRepository;
import com.dreamsecurity.sso.agent.provider.CommonProvider;
import com.dreamsecurity.sso.agent.token.SSOToken;
import com.dreamsecurity.sso.lib.dss.Configuration;
import com.dreamsecurity.sso.lib.dss.s2.core.Attribute;
import com.dreamsecurity.sso.lib.dss.s2.core.AttributeStatement;
import com.dreamsecurity.sso.lib.dss.s2.core.AttributeValue;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContext;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContextClassRef;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnStatement;
import com.dreamsecurity.sso.lib.dss.s2.core.Conditions;
import com.dreamsecurity.sso.lib.dss.s2.core.Issuer;
import com.dreamsecurity.sso.lib.dss.s2.core.LogoutRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.NameID;
import com.dreamsecurity.sso.lib.dss.s2.core.NameIDType;
import com.dreamsecurity.sso.lib.dss.s2.core.Status;
import com.dreamsecurity.sso.lib.dss.s2.core.StatusCode;
import com.dreamsecurity.sso.lib.dss.s2.core.Subject;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmation;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmationData;
import com.dreamsecurity.sso.lib.dss.s2.core.impl.AttributeBuilder;
import com.dreamsecurity.sso.lib.dss.s2.metadata.AssertionConsumerService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.Endpoint;
import com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SingleLogoutService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SingleSignOnService;
import com.dreamsecurity.sso.lib.dsx.XMLObject;
import com.dreamsecurity.sso.lib.dsx.XMLObjectBuilder;
import com.dreamsecurity.sso.lib.dsx.XMLObjectBuilderFactory;
import com.dreamsecurity.sso.lib.dsx.encryption.CipherData;
import com.dreamsecurity.sso.lib.dsx.encryption.CipherValue;
import com.dreamsecurity.sso.lib.dsx.io.Marshaller;
import com.dreamsecurity.sso.lib.dsx.io.MarshallingException;
import com.dreamsecurity.sso.lib.dsx.schema.XSString;
import com.dreamsecurity.sso.lib.dsx.signature.KeyInfo;
import com.dreamsecurity.sso.lib.dsx.signature.KeyValue;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.xsc.utils.Base64;

public class SAMLUtil
{
	private static Logger log = LoggerFactory.getInstance().getLogger(SAMLUtil.class);

	public static String createSamlId()
	{
		if (SSOConfig.getInstance().isSamlId()) {
			return Util.generateUUID();
		}
		else {
			try {
				return "SP-" + SSOCryptoApi.getInstance().createRandom(16);
			}
			catch (CryptoApiException e) {
				e.printStackTrace();
				return Util.generateUUID();
			}
		}
	}

	public static String getSPResponseURL(String baseURL, String spName)
	{
		String responseURL = "";

		try {
			SPSSODescriptor spDescriptor = MetadataRepository.getInstance().getSPDescriptor(spName);
			List<AssertionConsumerService> services = spDescriptor.getAssertionConsumerServices();

			for (int i = 0; i < services.size(); i++) {
				AssertionConsumerService service = (AssertionConsumerService) services.get(i);

				int nIndex = service.getLocation().indexOf(baseURL);
				if (nIndex >= 0) {
					responseURL = service.getLocation();
					break;
				}
			}

			if (Util.isEmpty(responseURL)) {
				log.error("### SP ResponseURL Empty [BaseURL: " + baseURL + "]");
			}

			return responseURL;
		}
		catch (SSOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public static String getIdpRequestURL()
	{
		return getIdpRequestURL("");
	}

	public static String getIdpRequestURL(String id)
	{
		String result = "";

		try {
			IDPSSODescriptor idpDescriptor = MetadataRepository.getInstance().getIDPDescriptor();

			if (Util.isEmpty(id)) {
				return idpDescriptor.getSingleSignOnServices().get(0).getLocation();
			}

			List<SingleSignOnService> services = idpDescriptor.getSingleSignOnServices();

			for (int i = 0; i < services.size(); i++) {
				if (Util.isEmpty(services.get(i).getBinding())) {
					continue;
				}

				if (services.get(i).getBinding().equals(id)) {
					result = services.get(i).getLocation();
					break;
				}
			}

			if (Util.isEmpty(result)) {
				return idpDescriptor.getSingleSignOnServices().get(0).getLocation();
			}
		}
		catch (SSOException e) {
			e.printStackTrace();
		}

		return result;
	}

	public static String getIdpLogoutURL()
	{
		return getIdpLogoutURL("");
	}

	public static String getIdpLogoutURL(String id)
	{
		String result = "";

		try {
			IDPSSODescriptor idpDescriptor = MetadataRepository.getInstance().getIDPDescriptor();

			if (Util.isEmpty(id)) {
				return idpDescriptor.getSingleLogoutServices().get(0).getLocation();
			}

			List<SingleLogoutService> services = idpDescriptor.getSingleLogoutServices();

			for (int i = 0; i < services.size(); i++) {
				if (Util.isEmpty(services.get(i).getBinding())) {
					continue;
				}

				if (services.get(i).getBinding().equals(id)) {
					result = services.get(i).getLocation();
					break;
				}
			}

			if (Util.isEmpty(result)) {
				return idpDescriptor.getSingleLogoutServices().get(0).getLocation();
			}
		}
		catch (SSOException e) {
			e.printStackTrace();
		}

		return result;
	}

	public static XMLObject buildXMLObject(QName qName)
	{
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XMLObjectBuilder<?> builder = builderFactory.getBuilder(qName);
		return builder.buildObject(qName);
	}


	public static void checkAndMarshall(XMLObject xmlObject) throws MarshallingException
	{
		Element targetElement = xmlObject.getDOM();
		if (targetElement == null) {
			Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
			marshaller.marshall(xmlObject);
		}
	}

	public static CipherData getCipherData(String encStr)
	{
		CipherValue cipherValue = (CipherValue) buildXMLObject(CipherValue.DEFAULT_ELEMENT_NAME);
		cipherValue.setValue(encStr);
		CipherData cipherData = (CipherData) buildXMLObject(CipherData.DEFAULT_ELEMENT_NAME);
		cipherData.setCipherValue(cipherValue);
		return cipherData;
	}

	public static Status makeStatus(String statCode)
	{
		Status status = (Status) SAMLUtil.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = (StatusCode) SAMLUtil.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
		statusCode.setValue(statCode);
		status.setStatusCode(statusCode);
		return status;
	}

	public static AttributeStatement makeAttributeStatement(SSOToken user)
	{
		AttributeStatement attrStatement = (AttributeStatement) buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
		List attributes = attrStatement.getAttributes();
		List propertyNames = user.getPropertyNames();
		String propertyName;

		for (int i = 0; i < propertyNames.size(); i++) {
			propertyName = (String) propertyNames.get(i);
			addAttriibute(attributes, propertyName, user.getProperty(propertyName));
		}

		addAttriibute(attributes, SSOToken.PROP_NAME_TOKEN_VALUE, user.getTokenValue().toString());
		return attrStatement;
	}

	private static void addAttriibute(List attributes, String name, String value)
	{
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		AttributeBuilder attrbuilder = new AttributeBuilder();
		XMLObjectBuilder attrvaluebuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
		Attribute attribute = attrbuilder.buildObject();
		attribute.setName(name);
		XSString attrvalue = (XSString) attrvaluebuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		attrvalue.setValue(value);
		attribute.getAttributeValues().add(attrvalue);
		attributes.add(attribute);
	}

	public static Issuer makeIssuer()
	{
		Issuer issuer = (Issuer) buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(SSOConfig.getInstance().getServerName());
		return issuer;
	}

	public static AuthnStatement makeAuthnStatement()
	{
		AuthnStatement authnStatement = (AuthnStatement) buildXMLObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnInstant(new DateTime());
		AuthnContext authnContext = (AuthnContext) buildXMLObject(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContextClassRef xmlObject = (AuthnContextClassRef) buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		xmlObject.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
		authnContext.setAuthnContextClassRef(xmlObject);
		authnStatement.setAuthnContext(authnContext);
		return authnStatement;
	}

	public static Conditions makeConditions()
	{
		Conditions conditions = (Conditions) buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
		DateTime dateTime = new DateTime();
		conditions.setNotBefore(dateTime.minusDays(1));
		conditions.setNotOnOrAfter(dateTime.plusDays(1));
		return conditions;
	}

	public static void printXMLObject(XMLObject response)
	{
		try {
			checkAndMarshall(response);
			// log.debug(Util.getIdx()+"XmlString = " +
			// Util.domToStr(response.getDOM().getOwnerDocument(), true));
		}
		catch (MarshallingException e) {
			// log.error("Error marshalling target XMLObject = " + response, e);
		}
	}

	public static Subject makeSubject(String id)
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		NameID nameid = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameIDType.ENTITY);
		nameid.setValue(id);
		subject.setNameID(nameid);

		return subject;
	}

	public static Subject makeAuthSubject(String id, String encPwd, String encApplCode, String encSessionid, String encIp)
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		/***
		String encid = null;
		try {
			encid = new String(Hex.encode(id.getBytes("8859_1")));
		}
		catch (Exception e) {
			encid = id;
		}
		***/

		NameID nameid = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameID.ENTITY);
		nameid.setValue(id);
		subject.setNameID(nameid);

		SubjectConfirmation subjConfirm = (SubjectConfirmation) buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjConfirm.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);
		SubjectConfirmationData subjConfirmdata = (SubjectConfirmationData) buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		// subjConfirmdata.setSchemaLocation();

		// pw encryption
		KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		KeyValue keyValue = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedPwd = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedPwd.setValue(encPwd);
		keyValue.setUnknownXMLObject(encryptedPwd);
		keyInfo.getKeyValues().add(keyValue);

		// sessionid encryption
		KeyValue keyValue_sess = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedSessKey = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedSessKey.setValue(encSessionid);
		keyValue_sess.setUnknownXMLObject(encryptedSessKey);
		keyInfo.getKeyValues().add(keyValue_sess);

		// applcode encryption
		KeyValue keyValue_appl = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedApplCode = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedApplCode.setValue(encApplCode);
		keyValue_appl.setUnknownXMLObject(encryptedApplCode);
		keyInfo.getKeyValues().add(keyValue_appl);

		// IP encryption
		KeyValue keyValue_ip = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedIp = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedIp.setValue(encIp);
		keyValue_ip.setUnknownXMLObject(encryptedIp);
		keyInfo.getKeyValues().add(keyValue_ip);

		subjConfirmdata.getUnknownXMLObjects().add(keyInfo);
		subjConfirm.setSubjectConfirmationData(subjConfirmdata);
		subject.getSubjectConfirmations().add(subjConfirm);

		return subject;
	}

	public static Subject makeAuthSubject(String id, String encPwd, String encApplCode, String encSessKey, String encIp, String encOtp)
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		/***
		String encid = null;
		try {
			encid = new String(Hex.encode(id.getBytes("8859_1")));
		}
		catch (Exception e) {
			encid = id;
		}
		***/

		NameID nameid = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameID.ENTITY);
		nameid.setValue(id);
		subject.setNameID(nameid);

		SubjectConfirmation subjConfirm = (SubjectConfirmation) buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjConfirm.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);
		SubjectConfirmationData subjConfirmdata = (SubjectConfirmationData) buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		// subjConfirmdata.setSchemaLocation();

		KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);

		// pw encryption
		KeyValue keyValue = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedPwd = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedPwd.setValue(encPwd);
		keyValue.setUnknownXMLObject(encryptedPwd);
		keyInfo.getKeyValues().add(keyValue);

		// sessKey encryption
		KeyValue keyValue_sess = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedSessKey = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedSessKey.setValue(encSessKey);
		keyValue_sess.setUnknownXMLObject(encryptedSessKey);
		keyInfo.getKeyValues().add(keyValue_sess);

		// applcode encryption
		KeyValue keyValue_appl = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedApplCode = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedApplCode.setValue(encApplCode);
		keyValue_appl.setUnknownXMLObject(encryptedApplCode);
		keyInfo.getKeyValues().add(keyValue_appl);

		// IP encryption
		KeyValue keyValue_ip = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedIp = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedIp.setValue(encIp);
		keyValue_ip.setUnknownXMLObject(encryptedIp);
		keyInfo.getKeyValues().add(keyValue_ip);

		// OTP encryption
		KeyValue keyValue_otp = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedOtp = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedOtp.setValue(encOtp);
		keyValue_otp.setUnknownXMLObject(encryptedOtp);
		keyInfo.getKeyValues().add(keyValue_otp);

		subjConfirmdata.getUnknownXMLObjects().add(keyInfo);
		subjConfirm.setSubjectConfirmationData(subjConfirmdata);
		subject.getSubjectConfirmations().add(subjConfirm);

		return subject;
	}

	public static Subject makeAuthSubject(String encApplCode, String encSessKey, String encIp)
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		NameID nameid = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameID.ENTITY);
		nameid.setValue(CommonProvider.SUBJECT_EMPTY_ID);
		subject.setNameID(nameid);

		SubjectConfirmation subjConfirm = (SubjectConfirmation) buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjConfirm.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);
		SubjectConfirmationData subjConfirmdata = (SubjectConfirmationData) buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		// subjConfirmdata.setSchemaLocation();

		KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);

		// dummy
		KeyValue keyValue = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString dummy = (XSString) buildXMLObject(XSString.TYPE_NAME);
		dummy.setValue("dummy");
		keyValue.setUnknownXMLObject(dummy);
		keyInfo.getKeyValues().add(keyValue);

		// sesskey encryption
		KeyValue keyValue_sess = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedSessKey = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedSessKey.setValue(encSessKey);
		keyValue_sess.setUnknownXMLObject(encryptedSessKey);
		keyInfo.getKeyValues().add(keyValue_sess);

		// applcode encryption
		KeyValue keyValue_appl = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedApplCode = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedApplCode.setValue(encApplCode);
		keyValue_appl.setUnknownXMLObject(encryptedApplCode);
		keyInfo.getKeyValues().add(keyValue_appl);

		// IP encryption
		KeyValue keyValue_ip = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString encryptedIp = (XSString) buildXMLObject(XSString.TYPE_NAME);
		encryptedIp.setValue(encIp);
		keyValue_ip.setUnknownXMLObject(encryptedIp);
		keyInfo.getKeyValues().add(keyValue_ip);

		subjConfirmdata.getUnknownXMLObjects().add(keyInfo);
		subjConfirm.setSubjectConfirmationData(subjConfirmdata);
		subject.getSubjectConfirmations().add(subjConfirm);

		return subject;
	}

	public static Subject makeNologinSubject()
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		NameID nameid = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameID.UNSPECIFIED);
		nameid.setValue("NONE_LOGIN");
		subject.setNameID(nameid);

		return subject;
	}

	public static Subject makeNologinSubject(boolean isAcl, String encApplCode, String encSessKey, String encIp)
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		NameID nameid = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameID.UNSPECIFIED);
		nameid.setValue("NONE_LOGIN");
		subject.setNameID(nameid);

		if (isAcl) {
			SubjectConfirmation subjConfirm = (SubjectConfirmation) buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
			subjConfirm.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);
			SubjectConfirmationData subjConfirmdata = (SubjectConfirmationData) buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);

			KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
			// dummy - index를 맞추기 위해추가
			KeyValue keyValue = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
			XSString dummy = (XSString) buildXMLObject(XSString.TYPE_NAME);
			dummy.setValue("dummy");
			keyValue.setUnknownXMLObject(dummy);
			keyInfo.getKeyValues().add(keyValue);

			// sesskey encryption
			KeyValue keyValue_sess = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
			XSString encryptedSessKey = (XSString) buildXMLObject(XSString.TYPE_NAME);
			encryptedSessKey.setValue(encSessKey);
			keyValue_sess.setUnknownXMLObject(encryptedSessKey);
			keyInfo.getKeyValues().add(keyValue_sess);

			// applcode encryption
			KeyValue keyValue_appl = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
			XSString encryptedApplCode = (XSString) buildXMLObject(XSString.TYPE_NAME);
			encryptedApplCode.setValue(encApplCode);
			keyValue_appl.setUnknownXMLObject(encryptedApplCode);
			keyInfo.getKeyValues().add(keyValue_appl);

			// IP encryption
			KeyValue keyValue_ip = (KeyValue) buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
			XSString encryptedIp = (XSString) buildXMLObject(XSString.TYPE_NAME);
			encryptedIp.setValue(encIp);
			keyValue_ip.setUnknownXMLObject(encryptedIp);
			keyInfo.getKeyValues().add(keyValue_ip);

			subjConfirmdata.getUnknownXMLObjects().add(keyInfo);
			subjConfirm.setSubjectConfirmationData(subjConfirmdata);
			subject.getSubjectConfirmations().add(subjConfirm);
		}

		return subject;
	}

	public static String makeNLAuthnRequest(String target, String id, DateTime issueTime, String encData, String encKey) throws Exception
	{
		AuthnRequest authnRequest = (AuthnRequest) SAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
		authnRequest.setDestination(target);
		authnRequest.setID(id);
		authnRequest.setIssueInstant(issueTime);

		// Issuer
		Issuer issuer = (Issuer) SAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(SSOConfig.getInstance().getServerName());

		authnRequest.setIssuer(issuer);

		// Subject
		Subject subject = (Subject) SAMLUtil.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		NameID nameid = (NameID) SAMLUtil.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameID.ENTITY);
		nameid.setValue(SSOConfig.getInstance().getServerName());

		subject.setNameID(nameid);

		SubjectConfirmation subjConfirm = (SubjectConfirmation) SAMLUtil.buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjConfirm.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);

		SubjectConfirmationData subjConfirmdata = (SubjectConfirmationData) SAMLUtil.buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = (KeyInfo) SAMLUtil.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);

		KeyValue keyValue_0 = (KeyValue) SAMLUtil.buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString xsString_0 = (XSString) SAMLUtil.buildXMLObject(XSString.TYPE_NAME);
		xsString_0.setValue(encData);
		keyValue_0.setUnknownXMLObject(xsString_0);
		keyInfo.getKeyValues().add(keyValue_0);

		KeyValue keyValue_1 = (KeyValue) SAMLUtil.buildXMLObject(KeyValue.DEFAULT_ELEMENT_NAME);
		XSString xsString_1 = (XSString) SAMLUtil.buildXMLObject(XSString.TYPE_NAME);
		xsString_1.setValue(encKey);
		keyValue_1.setUnknownXMLObject(xsString_1);
		keyInfo.getKeyValues().add(keyValue_1);

		subjConfirmdata.getUnknownXMLObjects().add(keyInfo);
		subjConfirm.setSubjectConfirmationData(subjConfirmdata);

		subject.getSubjectConfirmations().add(subjConfirm);
		authnRequest.setSubject(subject);

		// Sign
		SSOCryptoApi.getInstance().generateSignedXML(authnRequest);

		checkAndMarshall(authnRequest);
		String authnStr = Util.domToStr(authnRequest.getDOM().getOwnerDocument(), false);
		String encAuthn = Base64.encode(authnStr.getBytes()).replace("\n", "");

		return encAuthn;
	}

	public static X509Certificate getCert(String filepath)
	{
		try {
			InputStream input = new FileInputStream(filepath);
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");

			return (X509Certificate) certificateFactory.generateCertificate(input);
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static boolean sendAuthnRequest(HttpServletResponse response, XMLObject authnRequest, String requestType, String relayState)
	{
		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String endpoint = ((AuthnRequest) authnRequest).getDestination();

			if (Util.isEmpty(endpoint)) {
				endpoint = idp.getSingleSignOnServices().get(0).getLocation();
			}

			SAMLUtil.checkAndMarshall(authnRequest);
			String authnStr = Util.domToStr(authnRequest.getDOM().getOwnerDocument(), false);
			String encAuthn = Base64.encode(authnStr.getBytes()).replace("\n", "");

			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\" defer=\"defer\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(endpoint).append("\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("    <input type=\"hidden\" id=\"SAMLRequest\" name=\"SAMLRequest\" value=\"").append(encAuthn).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"RequestType\" name=\"RequestType\" value=\"").append(requestType).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"");
			if (relayState != null) {
				str.append(relayState);
			}
			str.append("\"/>\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	public static boolean sendLogoutRequest(XMLObject logoutRequest, String relayState, HttpServletResponse response)
	{
		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			String endpoint = ((LogoutRequest) logoutRequest).getDestination();

			if (Util.isEmpty(endpoint)) {
				endpoint = idp.getSingleLogoutServices().get(0).getLocation();
			}

			SAMLUtil.checkAndMarshall(logoutRequest);
			String logoutStr = Util.domToStr(logoutRequest.getDOM().getOwnerDocument(), false);
			String encLogout = Base64.encode(logoutStr.getBytes()).replace("\n", "");

			StringBuffer str = new StringBuffer();
			str.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			str.append("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
			str.append("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n");
			str.append("<body onload=\"document.forms[0].submit()\">\n");
			str.append("<form method=\"post\" action=\"").append(endpoint).append("\">\n");
			str.append("<div>\n");
			str.append("    <input type=\"hidden\" name=\"SAMLRequest\" value=\"").append(encLogout).append("\"/>\n");
			str.append("    <input type=\"hidden\" name=\"RelayState\" value=\"");
			if (relayState != null)
				str.append(relayState);
			str.append("\"/>\n");
			str.append("</div>\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Cache-control", "no-cache, no-store");
			response.setHeader("Pragma", "no-cache");
			response.setHeader("Content-Type", "text/html; charset=UTF-8");
			response.setCharacterEncoding("UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	public static boolean sendLogoutResponse(XMLObject logoutResponse, HttpServletResponse response)
	{
		try {
			SAMLUtil.checkAndMarshall(logoutResponse);
			String logoutStr = Util.domToStr(logoutResponse.getDOM().getOwnerDocument(), false);
			String encLogout = Base64.encode(logoutStr.getBytes()).replace("\n", "");

			PrintWriter out = response.getWriter();
			out.write(encLogout);
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	public static void sendIDPLogout(HttpServletResponse response, String relayState, String dupinfo, String brclose, String idp)
	{
		try {
			String target = getIdpLogoutURL(idp);

			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\" defer=\"defer\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(target).append("\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("    <input type=\"hidden\" id=\"dup\" name=\"dup\" value=\"").append(dupinfo).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"cl\" name=\"cl\" value=\"").append(brclose).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"SPName\" name=\"SPName\" value=\"").
					append(SSOConfig.getInstance().getServerName()).append("\"/>\n");
			str.append("    <input type=\"hidden\" id=\"RelayState\" name=\"RelayState\" value=\"");
			if (relayState != null) {
				str.append(relayState);
			}
			str.append("\"/>\n");
			str.append("</form>\n");
			str.append("</body>\n");
			str.append("</html>");

			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendPostLogout(String sendURL, String homeURL, String ssoId, String others, String dup, String prevIp,
			HttpServletResponse response)
	{
		try {
			StringBuffer str = new StringBuffer();
			str.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			str.append("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
			str.append("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n");

			if (sendURL.equalsIgnoreCase(homeURL) && others.equalsIgnoreCase("no")) {
				str.append("<script type=\"text/javascript\">\n");

				if (dup.equalsIgnoreCase("y")) {
					str.append("    alert(\" 다른 PC [").append(prevIp).append("] 에서 로그인하여 자동로그아웃 합니다.\");");
				}

				str.append("    parent.location.href=\"").append(homeURL).append("\";\n");
				str.append("</script>\n");
				str.append("</html>\n");
			}
			else {
				str.append("<body onload=\"document.forms[0].submit()\">\n");
				str.append("<form method=\"post\" action=\"").append(sendURL).append("\">\n");
				str.append("<div>\n");
				str.append("    <input type=\"hidden\" name=\"homeURL\" value=\"").append(homeURL).append("\"/>\n");
				str.append("    <input type=\"hidden\" name=\"ssoId\" value=\"").append(ssoId).append("\"/>\n");
				str.append("    <input type=\"hidden\" name=\"others\" value=\"").append(others).append("\"/>\n");
				str.append("    <input type=\"hidden\" name=\"dup\" value=\"").append(dup).append("\"/>\n");
				str.append("    <input type=\"hidden\" name=\"prevIp\" value=\"").append(prevIp).append("\"/>\n");
				str.append("</div>\n");
				str.append("</form>\n");
				str.append("</body>\n");
				str.append("</html>");
			}

			response.setHeader("Cache-control", "no-cache, no-store");
			response.setHeader("Pragma", "no-cache");
			response.setHeader("Content-Type", "text/html; charset=UTF-8");
			response.setCharacterEncoding("UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
