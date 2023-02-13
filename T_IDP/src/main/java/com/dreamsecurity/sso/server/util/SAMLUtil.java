package com.dreamsecurity.sso.server.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import com.dreamsecurity.sso.lib.dss.Configuration;
import com.dreamsecurity.sso.lib.dss.cn.xml.SAMLConstants;
import com.dreamsecurity.sso.lib.dss.s2.core.Assertion;
import com.dreamsecurity.sso.lib.dss.s2.core.Attribute;
import com.dreamsecurity.sso.lib.dss.s2.core.AttributeStatement;
import com.dreamsecurity.sso.lib.dss.s2.core.AttributeValue;
import com.dreamsecurity.sso.lib.dss.s2.core.Audience;
import com.dreamsecurity.sso.lib.dss.s2.core.AudienceRestriction;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContext;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContextClassRef;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnStatement;
import com.dreamsecurity.sso.lib.dss.s2.core.Conditions;
import com.dreamsecurity.sso.lib.dss.s2.core.Issuer;
import com.dreamsecurity.sso.lib.dss.s2.core.NameID;
import com.dreamsecurity.sso.lib.dss.s2.core.NameIDType;
import com.dreamsecurity.sso.lib.dss.s2.core.Response;
import com.dreamsecurity.sso.lib.dss.s2.core.Status;
import com.dreamsecurity.sso.lib.dss.s2.core.StatusCode;
import com.dreamsecurity.sso.lib.dss.s2.core.Subject;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmation;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmationData;
import com.dreamsecurity.sso.lib.dss.s2.core.impl.AttributeBuilder;
import com.dreamsecurity.sso.lib.dss.s2.metadata.AssertionConsumerService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.Endpoint;
import com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.RequestedAttribute;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor;
import com.dreamsecurity.sso.lib.dsx.XMLObject;
import com.dreamsecurity.sso.lib.dsx.XMLObjectBuilder;
import com.dreamsecurity.sso.lib.dsx.XMLObjectBuilderFactory;
import com.dreamsecurity.sso.lib.dsx.encryption.CipherData;
import com.dreamsecurity.sso.lib.dsx.encryption.CipherValue;
import com.dreamsecurity.sso.lib.dsx.io.Marshaller;
import com.dreamsecurity.sso.lib.dsx.io.MarshallingException;
import com.dreamsecurity.sso.lib.dsx.schema.XSString;
import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.security.x509.BasicX509Credential;
import com.dreamsecurity.sso.lib.dsx.signature.KeyInfo;
import com.dreamsecurity.sso.lib.dsx.signature.KeyValue;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.xsc.utils.Base64;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.provider.CommonProvider;
import com.dreamsecurity.sso.server.token.SSOToken;

public class SAMLUtil
{
	public static String createSamlId(String prefix)
	{
		if (SSOConfig.getInstance().isSamlId()) {
			return Util.generateUUID();
		}
		else {
			try {
				return prefix + SSOCryptoApi.getInstance().createRandom(16);
			}
			catch (CryptoApiException e) {
				e.printStackTrace();
				return prefix + Util.generateUUID();
			}
		}
	}

	public static String createSamlId_()
	{
		if (SSOConfig.getInstance().isSamlId()) {
			return Util.generateUUID();
		}
		else {
			try {
				return SSOCryptoApi.getInstance().createRandom(16);
			}
			catch (CryptoApiException e) {
				e.printStackTrace();
				return Util.generateUUID();
			}
		}
	}

	public static Credential createCredential(String name, X509Certificate cert)
	{
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityId(name);
		credential.setEntityCertificate(cert);
		credential.setPublicKey(cert.getPublicKey());

		return credential;
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

	public static Response makeResponse(String authnID, String sid, DateTime issueTime)
	{
		Response response = (Response) SAMLUtil.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
		response.setID(sid);
		response.setInResponseTo(authnID);
		response.setIssueInstant(issueTime);

		Status status = makeStatus(StatusCode.SUCCESS_URI);

		response.setStatus(status);
		return response;
	}

	public static Status makeStatus(String value)
	{
		Status status = (Status) SAMLUtil.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);

		StatusCode statusCode = (StatusCode) SAMLUtil.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
		statusCode.setValue(value);

		status.setStatusCode(statusCode);
		return status;
	}

	public static AttributeStatement makeAttributeStatement(SSOToken token, String IDPSessionID)
	{
		AttributeStatement attrStatement = (AttributeStatement) buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
		List<Attribute> attributes = attrStatement.getAttributes();

		addAttriibute(attributes, "IDP_JSESSIONID", IDPSessionID);
		addAttriibute(attributes, SSOToken.PROP_NAME_TOKEN_VALUE, token.getTokenValue().toString());
		return attrStatement;
	}

	public static AttributeStatement makeAttributeStatement(String sendData)
	{
		AttributeStatement attrStatement = (AttributeStatement) buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
		List<Attribute> attributes = attrStatement.getAttributes();

		addAttriibute(attributes, "AUTHN_INFO", sendData);
		return attrStatement;
	}

    private static void addAttriibute(List<Attribute> attributes, String name, String value)
    {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        AttributeBuilder attrbuilder = new AttributeBuilder();
        XMLObjectBuilder<?> attrvaluebuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
        Attribute attribute = attrbuilder.buildObject();
        attribute.setName(name);
        XSString attrvalue = (XSString)attrvaluebuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attrvalue.setValue(value);
        attribute.getAttributeValues().add(attrvalue);
        attributes.add(attribute);
    }

	public static Issuer makeIssuer(String serverName)
	{
		Issuer issuer = (Issuer) buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(serverName);
		return issuer;
	}

	public static AuthnStatement makeAuthnStatement(DateTime authnIssue, String value)
	{
		AuthnStatement authnStatement = (AuthnStatement) buildXMLObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnInstant(authnIssue);

		AuthnContext authnContext = (AuthnContext) buildXMLObject(AuthnContext.DEFAULT_ELEMENT_NAME);

		AuthnContextClassRef xmlObject = (AuthnContextClassRef) buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		xmlObject.setAuthnContextClassRef(value);

		authnContext.setAuthnContextClassRef(xmlObject);
		authnStatement.setAuthnContext(authnContext);
		return authnStatement;
	}

	public static Conditions makeConditions(DateTime issueTime)
	{
		Conditions conditions = (Conditions) buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
		conditions.setNotBefore(issueTime.minusDays(1));
		conditions.setNotOnOrAfter(issueTime.plusDays(1));
		return conditions;
	}

	public static Subject makeSubject(String id, String authnID)
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

		NameID nameid = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameid.setFormat(NameIDType.ENTITY);
		nameid.setValue(id);

		subject.setNameID(nameid);

		SubjectConfirmation subjectconf = (SubjectConfirmation) buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjectconf.setMethod(SubjectConfirmation.METHOD_BEARER);

		SubjectConfirmationData subjectconfdata = (SubjectConfirmationData) buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		subjectconfdata.setInResponseTo(authnID);

		subjectconf.setSubjectConfirmationData(subjectconfdata);
		subject.getSubjectConfirmations().add(subjectconf);
		return subject;
	}

	public static Response makeStdResponse(String sid, DateTime issueTime, String destination, String authnID)
	{
		QName qname = new QName(SAMLConstants.SAML20P_NS, Response.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
		Response response = (Response) SAMLUtil.buildXMLObject(qname);
		response.setDestination(destination);
		response.setID(sid);
		response.setInResponseTo(authnID);
		response.setIssueInstant(issueTime);

		return response;
	}

	public static Assertion makeStdAssertion(String sid, DateTime issueTime)
	{
		QName qname = new QName(SAMLConstants.SAML20_NS, Assertion.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		Assertion assertion = (Assertion) SAMLUtil.buildXMLObject(qname);
		assertion.setID(sid);
		assertion.setIssueInstant(issueTime);

		return assertion;
	}

	public static Status makeStdStatus(String value)
	{
		QName sqname = new QName(SAMLConstants.SAML20P_NS, StatusCode.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
		StatusCode statusCode = (StatusCode) SAMLUtil.buildXMLObject(sqname);
		statusCode.setValue(value);

		QName qname = new QName(SAMLConstants.SAML20P_NS, Status.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
		Status status = (Status) SAMLUtil.buildXMLObject(qname);
		status.setStatusCode(statusCode);

		return status;
	}

	public static Issuer makeStdIssuer(String serverName)
	{
		QName qname = new QName(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		Issuer issuer = (Issuer) buildXMLObject(qname);
		issuer.setValue(serverName);

		return issuer;
	}

	public static Subject makeStdSubject(String useID, String nameIDType, DateTime issueTime, String destination,
			String serverName, String spName, String authnID, String immutableID)
	{
		QName nameidQname = new QName(SAMLConstants.SAML20_NS, NameID.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		NameID nameid = (NameID) buildXMLObject(nameidQname);
		nameid.setFormat(nameIDType);
		
		if (Util.isEmpty(immutableID)) {
			nameid.setNameQualifier(serverName);
			nameid.setSPNameQualifier(spName);

			if (nameIDType.equals(NameIDType.PERSISTENT) || nameIDType.equals(NameIDType.TRANSIENT)) {
				nameid.setValue(createSamlId("_"));
			} else {
				nameid.setValue(useID);
			}
		} else {
			nameid.setValue(immutableID);
		}

		QName subjectconfdataQname = new QName(SAMLConstants.SAML20_NS, SubjectConfirmationData.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		SubjectConfirmationData subjectconfdata = (SubjectConfirmationData) buildXMLObject(subjectconfdataQname);
		subjectconfdata.setInResponseTo(authnID);
		subjectconfdata.setNotOnOrAfter(issueTime.plusMinutes(5));
		subjectconfdata.setRecipient(destination);

		QName subjectconfQname = new QName(SAMLConstants.SAML20_NS, SubjectConfirmation.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		SubjectConfirmation subjectconf = (SubjectConfirmation) buildXMLObject(subjectconfQname);
		subjectconf.setMethod(SubjectConfirmation.METHOD_BEARER);
		subjectconf.setSubjectConfirmationData(subjectconfdata);

		QName subjectQname = new QName(SAMLConstants.SAML20_NS, Subject.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		Subject subject = (Subject) buildXMLObject(subjectQname);
		subject.setNameID(nameid);
		subject.getSubjectConfirmations().add(subjectconf);

		return subject;
	}

	public static Conditions makeStdConditions(DateTime issueTime, String spName)
	{
		QName audienceQname = new QName(SAMLConstants.SAML20_NS, Audience.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		Audience audience = (Audience) buildXMLObject(audienceQname);
		audience.setAudienceURI(spName);

		QName audiencerestQname = new QName(SAMLConstants.SAML20_NS, AudienceRestriction.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		AudienceRestriction audiencerest = (AudienceRestriction) buildXMLObject(audiencerestQname);
		audiencerest.getAudiences().add(audience);

		QName qname = new QName(SAMLConstants.SAML20_NS, Conditions.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		Conditions conditions = (Conditions) buildXMLObject(qname);
		conditions.setNotBefore(issueTime);
		conditions.setNotOnOrAfter(issueTime.plusMinutes(5));
		conditions.getAudienceRestrictions().add(audiencerest);

		return conditions;
	}

	public static AuthnStatement makeStdAuthnStatement(DateTime authnIssueTime)
	{
		QName classrefQname = new QName(SAMLConstants.SAML20_NS, AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		AuthnContextClassRef classref = (AuthnContextClassRef) buildXMLObject(classrefQname);
		classref.setAuthnContextClassRef(AuthnContext.IP_AUTHN_CTX);

		QName authncontextQname = new QName(SAMLConstants.SAML20_NS, AuthnContext.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		AuthnContext authnContext = (AuthnContext) buildXMLObject(authncontextQname);
		authnContext.setAuthnContextClassRef(classref);

		QName authnstateQname = new QName(SAMLConstants.SAML20_NS, AuthnStatement.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		AuthnStatement authnStatement = (AuthnStatement) buildXMLObject(authnstateQname);
		authnStatement.setAuthnInstant(authnIssueTime);
		authnStatement.setSessionIndex(createSamlId("_"));
		authnStatement.setAuthnContext(authnContext);

		return authnStatement;
	}

	public static AttributeStatement makeStdAttributeStatement(List<RequestedAttribute> attributeList, SSOToken token)
	{
		QName attrstatementQname = new QName(SAMLConstants.SAML20_NS, AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		AttributeStatement attrStatement = (AttributeStatement) buildXMLObject(attrstatementQname);
		List<Attribute> attributes = attrStatement.getAttributes();

		for (int i = 0; i < attributeList.size(); i++) {
			RequestedAttribute attr = attributeList.get(i);
			addStdAttriibute(attributes, attr.getNameFormat(), attr.getName(), token.getProperty(attr.getFriendlyName()));
		}

		return attrStatement;
	}

    private static void addStdAttriibute(List<Attribute> attributes, String nameFormat, String name, String value)
    {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XMLObjectBuilder<?> builder = builderFactory.getBuilder(XSString.TYPE_NAME);

		QName attrvalueQname = new QName(SAMLConstants.SAML20_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		XSString attrvalue = (XSString) builder.buildObject(attrvalueQname, XSString.TYPE_NAME);
		attrvalue.setValue(value);

		AttributeBuilder attrbuilder = new AttributeBuilder();
		Attribute attribute = attrbuilder.buildObject(SAMLConstants.SAML20_NS, Attribute.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		attribute.setName(name);
		attribute.setNameFormat(nameFormat);;
		attribute.getAttributeValues().add(attrvalue);

		attributes.add(attribute);
    }

	public static void printXMLObject(XMLObject response)
	{
		try {
			checkAndMarshall(response);
			// log.debug(Util.getIdx()+"XmlString = " +
			// Util.domToStr(response.getDOM().getOwnerDocument(), true));
		}
		catch (MarshallingException e) {
		}
	}

	public static Subject makeAuthSubject(String id, String encPwd, String encApplCode, String encSessionid, String encIp)
	{
		Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);
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
		// dummy - index를 맞추기 위해 추가
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

	/***
	public static String domToStr(Document doc, boolean indent)
	{
		OutputFormat of = new OutputFormat();

		String encoding = new OutputStreamWriter(System.out).getEncoding();
		if (!"UTF8".equals(encoding))
			of.setEncoding("EUC-KR");

		of.setIndenting(indent);
		of.setOmitXMLDeclaration(false);
		of.setLineWidth(130);

		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			BufferedWriter output = new BufferedWriter(new OutputStreamWriter(out));
			XMLSerializer serializer = new XMLSerializer(output, of);
			serializer.serialize(doc);
			return out.toString();
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public static String domToStr(Document doc, boolean indent, String encoding)
	{
		OutputFormat of = new OutputFormat();

		of.setEncoding(encoding);
		of.setIndenting(indent);
		of.setOmitXMLDeclaration(false);
		of.setLineWidth(130);

		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			BufferedWriter output = new BufferedWriter(new OutputStreamWriter(out));
			XMLSerializer serializer = new XMLSerializer(output, of);
			serializer.serialize(doc);
			return out.toString();
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
	***/

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

	public static void sendErrorURL(String url, HttpServletResponse response)
	{
		StringBuffer str = new StringBuffer();
		str.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		str.append("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
		str.append("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n");
		str.append("<body onload=\"document.forms[0].submit()\">\n");
		str.append("<form method=\"post\" action=\"").append(url).append("\">\n");
		str.append("</form>\n");
		str.append("</body>\n");
		str.append("</html>");

		try {
			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void sendErrorURL(String url, int ecode, String emessage, HttpServletResponse response)
	{
		StringBuffer str = new StringBuffer();
		str.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		str.append("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
		str.append("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n");
		str.append("<body onload=\"document.forms[0].submit()\">\n");
		str.append("<form method=\"post\" action=\"").append(url).append("\">\n");
		str.append("<div>\n");
		str.append("    <input type=\"hidden\" name=\"ecode\" value=\"").append(ecode).append("\"/>\n");
		str.append("    <input type=\"hidden\" name=\"emessage\" value=\"").append(emessage).append("\"/>\n");
		str.append("</div>\n");
		str.append("</form>\n");
		str.append("</body>\n");
		str.append("</html>");

		try {
			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(str.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static boolean sendAuthnRequest(XMLObject authnRequest, String relayState, HttpServletResponse response)
	{
		try {
			IDPSSODescriptor idp = MetadataRepository.getInstance().getIDPDescriptor();
			Endpoint endpoint = idp.getSingleSignOnServices().get(0);

			SAMLUtil.checkAndMarshall(authnRequest);
			String authnStr = Util.domToStr(authnRequest.getDOM().getOwnerDocument(), false);
			String encAuthn = Base64.encode(authnStr.getBytes()).replace("\n", "");

			StringBuffer str = new StringBuffer();
			str.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			str.append("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
			str.append("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n");
			str.append("<body onload=\"document.forms[0].submit()\">\n");
			str.append("<form method=\"post\" action=\"").append(endpoint.getLocation()).append("\">\n");
			str.append("<div>\n");
			str.append("    <input type=\"hidden\" name=\"SAMLRequest\" value=\"").append(encAuthn).append("\"/>\n");
			str.append("    <input type=\"hidden\" name=\"authParameter\" value=\"CreateRequestAuth.jsp\"/>\n");
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
			response.setCharacterEncoding("UTF-8");
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

	public static boolean sendResponse(HttpServletResponse response, XMLObject samlResponse, AuthnRequest authnRequest, String relayState)
	{
		try {
			SPSSODescriptor sp = MetadataRepository.getInstance().getSPDescriptor(authnRequest.getProviderName());
			Endpoint endpoint = getEndpoint(relayState, sp);

			SAMLUtil.checkAndMarshall(samlResponse);
			String strResponse = Util.domToStr(samlResponse.getDOM().getOwnerDocument(), false);
			String encResponse = Util.encode64(strResponse.getBytes()).replace("\n", "");

			StringBuffer str = new StringBuffer();
			str.append("<html>\n");
			str.append("<head>\n");
			str.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n");
			str.append("<title></title>\n");
			str.append("<script type=\"text/javascript\" defer=\"defer\">\n");
			str.append("function goNext() {\n");
			str.append("    var frm = document.getElementById(\"ssoForm\");\n");
			str.append("    frm.action = \"").append(endpoint.getLocation()).append("\";\n");
			str.append("    frm.submit();\n");
			str.append("}\n");
			str.append("</script>\n");
			str.append("</head>\n");
			str.append("<body onload=\"goNext(); return false;\">\n");
			str.append("<form id=\"ssoForm\" name=\"ssoForm\" method=\"post\">\n");
			str.append("    <input type=\"hidden\" id=\"SAMLResponse\" name=\"SAMLResponse\" value=\"").append(encResponse).append("\"/>\n");
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

	public static boolean sendResponse(HttpServletResponse response, Response samlResponse, String relayState)
	{
		try {
			String endpoint = samlResponse.getDestination();

			SAMLUtil.checkAndMarshall(samlResponse);
			String strResponse = Util.domToStr(samlResponse.getDOM().getOwnerDocument(), false);
			String encResponse = Util.encode64(strResponse.getBytes()).replace("\n", "");

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
			str.append("    <input type=\"hidden\" name=\"SAMLResponse\" value=\"").append(encResponse).append("\"/>\n");

			if (!Util.isEmpty(relayState)) {
				str.append("    <input type=\"hidden\" name=\"RelayState\" value=\"").append(relayState).append("\"/>\n");
			}

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

	public static void sendDupSPLogout(HttpServletResponse response, String dupData)
	{
		try {
			String[] arr = dupData.split(";");

			SPSSODescriptor sp = MetadataRepository.getInstance().getSPDescriptor(arr[3]);
			String target = sp.getSingleLogoutServices().get(0).getLocation();

			JSONObject jData = new JSONObject();
			jData.put("pip", arr[1]);
			jData.put("pbr", arr[2]);

			String encData = null;

			if (arr[3].substring(arr[3].length() - 2).equals("_S")) {
				jData.put("xid", Util.generateUUID());

				encData = SSOCryptoApi.getInstance().encryptJsonObject(jData, arr[3]);
			}
			else {
				jData.put("xfr", SSOConfig.getInstance().getServerName());
				jData.put("xto", arr[3]);

				encData = SSOCryptoApi.getInstance().encryptHttpParam(arr[3], target, jData);
			}

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
			str.append("    <input type=\"hidden\" id=\"ED\" name=\"ED\" value=\"").append(encData).append("\"/>\n");
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

		return;
	}

	public static Endpoint getEndpoint(String relayState, SPSSODescriptor spDesc)
	{
		String relay = null;

		try {
			relay = URLDecoder.decode(relayState, "UTF-8");
		}
		catch (Exception e) {
			e.printStackTrace();
			relay = relayState;
		}

		URL relayUrl = null;

		try {
			relayUrl = new URL(relay);
		}
		catch (Exception e) {
			return spDesc.getDefaultAssertionConsumerService();
		}

		String relayHost = relayUrl.getHost();

		if (Util.isEmpty(relayHost)) {
			return spDesc.getDefaultAssertionConsumerService();
		}

		List<AssertionConsumerService> serviceList = spDesc.getAssertionConsumerServices();

		for (int i = 0; i < serviceList.size(); i++) {
			AssertionConsumerService service = serviceList.get(i);

			try {
				if (relayHost.equals(new URL(service.getLocation()).getHost())) {
					return service;
				}
			}
			catch (Exception e) {
			}
		}

		return spDesc.getDefaultAssertionConsumerService();
	}
}