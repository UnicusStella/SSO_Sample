package com.dreamsecurity.sso.agent.provider;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.crypto.CryptoApiException;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.crypto.SSOSecretKey;
import com.dreamsecurity.sso.agent.exception.SSOException;
import com.dreamsecurity.sso.agent.ha.SyncManager;
import com.dreamsecurity.sso.agent.ha.SyncMonitor;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.metadata.CredentialRepository;
import com.dreamsecurity.sso.agent.metadata.MetadataRepository;
import com.dreamsecurity.sso.agent.token.SSOToken;
import com.dreamsecurity.sso.agent.util.SAMLUtil;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.dss.cn.binding.BasicSAMLMessageContext;
import com.dreamsecurity.sso.lib.dss.cn.binding.decoding.SAMLMessageDecoder;
import com.dreamsecurity.sso.lib.dss.s2.binding.decoding.HTTPPostDecoder;
import com.dreamsecurity.sso.lib.dss.s2.core.Assertion;
import com.dreamsecurity.sso.lib.dss.s2.core.Attribute;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContext;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContextClassRef;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContextComparisonTypeEnumeration;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.EncryptedAssertion;
import com.dreamsecurity.sso.lib.dss.s2.core.Issuer;
import com.dreamsecurity.sso.lib.dss.s2.core.NameID;
import com.dreamsecurity.sso.lib.dss.s2.core.RequestedAuthnContext;
import com.dreamsecurity.sso.lib.dss.s2.core.Response;
import com.dreamsecurity.sso.lib.dss.s2.core.Subject;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmation;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmationData;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor;
import com.dreamsecurity.sso.lib.dsw.message.MessageContext;
import com.dreamsecurity.sso.lib.dsw.transport.http.HttpServletRequestAdapter;
import com.dreamsecurity.sso.lib.dsw.transport.http.HttpServletResponseAdapter;
import com.dreamsecurity.sso.lib.dsx.io.MarshallingException;
import com.dreamsecurity.sso.lib.dsx.schema.XSString;
import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.signature.KeyInfo;
import com.dreamsecurity.sso.lib.dsx.signature.KeyValue;
import com.dreamsecurity.sso.lib.jsn.JSONArray;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormat;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormatter;

public class ServiceProvider extends CommonProvider
{
	private static ServiceProvider instance = null;

	private static Logger log = LoggerFactory.getInstance().getLogger(ServiceProvider.class);

	public static final String PARAM_SAMLREQUEST = "SAMLRequest";
	public static final String PARAM_SAMLRESPONSE = "SAMLResponse";
	public static final String PARAM_RELAYSTATE = "RelayState";

	ServiceProvider() throws SSOException
	{
		super();
	}

	public static ServiceProvider getInstance() throws SSOException
	{
		if (instance == null) {
			synchronized (ServiceProvider.class) {
				if (instance == null) {
					instance = new ServiceProvider();
				}
			}
		}

		return instance;
	}

	// Install Test
	public AuthnRequest generateAuthRequest()
	{
		AuthnRequest authnRequest = null;

		try {
			authnRequest = (AuthnRequest) SAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
			SAMLUtil.checkAndMarshall(authnRequest);
		}
		catch (MarshallingException e) {
			e.printStackTrace();
		}

		return authnRequest;
	}

	public JSONObject generateAuthnRequest(HttpServletRequest request, String id, String pw, String idp)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		/***
		String ch = request.getParameter("loginCh") == null ? "" : (String) request.getParameter("loginCh");
		String sessionCh = session.getAttribute("LPCHLG") == null ? "" : (String) session.getAttribute("LPCHLG");
		Date sessionTm = (Date) session.getAttribute("LPTIME");
		session.removeAttribute("LPCHLG");
		session.removeAttribute("LPTIME");

		if (sessionTm != null) {
			Date curDate = new Date(System.currentTimeMillis());
			Calendar cal = Calendar.getInstance();
			cal.setTime(sessionTm);
			cal.add(Calendar.MINUTE, SSOConfig.getInstance().getLoginCSRFTokenTime());
			sessionTm = cal.getTime();

			int compare = curDate.compareTo(sessionTm);
			if (compare > 0) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "Login CSRFToken Timeout");
				result.put("data", "");
				return result;
			}
		}
		else {
			sessionCh = "";
		}

		if (Util.isEmpty(sessionCh) || !sessionCh.equals(ch)) {
			Util.setAuditInfo(id, "AG", "1", "로그인 패킷 재사용");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "로그인 패킷 재사용");
			result.put("data", "");
			return result;
		}
		***/

		try {
			/***
			id = SSOCryptoApi.getInstance().decryptJS(ch, id);
			pw = SSOCryptoApi.getInstance().decryptJS(ch, pw);
			***/

			String sid = config.getServerSessionidkey() + "=" + request.getSession(true).getId();

			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);

			String xid = SAMLUtil.createSamlId();
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String xtime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			JSONObject sData = new JSONObject();
			sData.put("id", id);
			sData.put("pw", pw);
			sData.put("appl", config.getServerApplcode());
			sData.put("sid", sid);
			sData.put("spip", this.serverIP);
			sData.put("xid", xid);
			sData.put("xtm", xtime);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			// 암호키 생성
			SSOSecretKey secKey = cryptoApi.generateSecretKey();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AM", "0",
					id + "," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키,SEED/CBC");

			String encData = cryptoApi.encrypt(secKey, sData.toString());
			String encKey = cryptoApi.encryptPublicKey(idpCert, secKey.getKeyIv());

			// 암호키 분배
			if (SSOConfig.getInstance().isDistCryptoKey()) {
				SSOConfig.getInstance().setDistCryptoKey(false);
				Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AV", "0",
						MetadataRepository.getInstance().getIDPName());
			}

			// 암호키 파기
			Util.zeroize(pw);
			secKey.finalize();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AW", "0",
					id + "," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키 분배 후 파기,0 으로 덮어쓰기");

			String responseURL = SAMLUtil.getSPResponseURL(Util.getBaseURL(request), this.serverName);

			// AuthnRequest
			AuthnRequest authnRequest = (AuthnRequest) SAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
			authnRequest.setAssertionConsumerServiceURL(responseURL);
			authnRequest.setDestination(SAMLUtil.getIdpRequestURL(idp));
			authnRequest.setID(xid);
			authnRequest.setProviderName(this.serverName);
			authnRequest.setIssueInstant(issueTime);

			// Issuer
			Issuer issuer = (Issuer) SAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
			issuer.setSPProvidedID(this.serverName);
			issuer.setValue(this.serverName);

			authnRequest.setIssuer(issuer);

			// Subject
			Subject subject = (Subject) SAMLUtil.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

			NameID nameid = (NameID) SAMLUtil.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
			nameid.setFormat(NameID.ENTITY);
			nameid.setValue(id);

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

			// RequestedAuthnContext
			RequestedAuthnContext reqAuthnContext = (RequestedAuthnContext) SAMLUtil.buildXMLObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			reqAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			AuthnContextClassRef classref = (AuthnContextClassRef) SAMLUtil.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			classref.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

			reqAuthnContext.getAuthnContextClassRefs().add(classref);
			authnRequest.setRequestedAuthnContext(reqAuthnContext);

			// Sign
			SPSSODescriptor spDescriptor = MetadataRepository.getInstance().getSPDescriptor(this.serverName);

			if (spDescriptor.isAuthnRequestsSigned()) {
				SSOCryptoApi.getInstance().generateSignedXML(authnRequest);
			}
			else {
				SAMLUtil.checkAndMarshall(authnRequest);
			}

			// AuthnRequest XML String
//			SAMLUtil.checkAndMarshall(authnRequest);
//			Document document2 = authnRequest.getDOM().getOwnerDocument();
//			log.debug("### AuthnRequest XML String:\n" + Util.domToStr(document2, true));

			session.setAttribute("LGCHLG", "L" + authnRequest.getID());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", authnRequest);
			return result;
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateAuthnRequest() CryptoApiException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (SSOException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generateAuthnRequest() SSOException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() SSOException: " + e.getErrorCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_GENERATE));
			result.put("message", "generateAuthnRequest() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject generateAuthnRequestCert(HttpServletRequest request, String signedData, String idp)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		try {
			String sid = config.getServerSessionidkey() + "=" + request.getSession(true).getId();

			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);

			String xid = SAMLUtil.createSamlId();
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String xtime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			JSONObject sData = new JSONObject();
			sData.put("signed", signedData);
			sData.put("appl", config.getServerApplcode());
			sData.put("sid", sid);
			sData.put("spip", this.serverIP);
			sData.put("xid", xid);
			sData.put("xtm", xtime);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			// 암호키 생성
			SSOSecretKey secKey = cryptoApi.generateSecretKey();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AM", "0",
					"인증서," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키,SEED/CBC");

			String encData = cryptoApi.encrypt(secKey, sData.toString());
			String encKey = cryptoApi.encryptPublicKey(idpCert, secKey.getKeyIv());

			// 암호키 분배
			if (SSOConfig.getInstance().isDistCryptoKey()) {
				SSOConfig.getInstance().setDistCryptoKey(false);
				Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AV", "0",
						MetadataRepository.getInstance().getIDPName());
			}

			// 암호키 파기
			secKey.finalize();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AW", "0",
					"인증서," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키 분배 후 파기,0 으로 덮어쓰기");

			String responseURL = SAMLUtil.getSPResponseURL(Util.getBaseURL(request), this.serverName);

			// AuthnRequest
			AuthnRequest authnRequest = (AuthnRequest) SAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
			authnRequest.setAssertionConsumerServiceURL(responseURL);
			authnRequest.setDestination(SAMLUtil.getIdpRequestURL(idp));
			authnRequest.setID(xid);
			authnRequest.setProviderName(this.serverName);
			authnRequest.setIssueInstant(issueTime);

			// Issuer
			Issuer issuer = (Issuer) SAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
			issuer.setSPProvidedID(this.serverName);
			issuer.setValue(this.serverName);

			authnRequest.setIssuer(issuer);

			// Subject
			Subject subject = (Subject) SAMLUtil.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

			NameID nameid = (NameID) SAMLUtil.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
			nameid.setFormat(NameID.ENTITY);
			nameid.setValue(CommonProvider.SUBJECT_LOGIN_CERT);

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

			// RequestedAuthnContext
			RequestedAuthnContext reqAuthnContext = (RequestedAuthnContext) SAMLUtil.buildXMLObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			reqAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			AuthnContextClassRef classref = (AuthnContextClassRef) SAMLUtil.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			classref.setAuthnContextClassRef(AuthnContext.X509_AUTHN_CTX);

			reqAuthnContext.getAuthnContextClassRefs().add(classref);
			authnRequest.setRequestedAuthnContext(reqAuthnContext);

			// Sign
			SPSSODescriptor spDescriptor = MetadataRepository.getInstance().getSPDescriptor(this.serverName);

			if (spDescriptor.isAuthnRequestsSigned()) {
				SSOCryptoApi.getInstance().generateSignedXML(authnRequest);
			}
			else {
				SAMLUtil.checkAndMarshall(authnRequest);
			}

			// AuthnRequest XML String
//			SAMLUtil.checkAndMarshall(authnRequest);
//			Document document2 = authnRequest.getDOM().getOwnerDocument();
//			log.debug("### AuthnRequest XML String:\n" + Util.domToStr(document2, true));

			session.setAttribute("LGCHLG", "L" + authnRequest.getID());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", authnRequest);
			return result;
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateAuthnRequestCert() CryptoApiException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequestCert() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (SSOException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generateAuthnRequestCert() SSOException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequestCert() SSOException: " + e.getErrorCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_GENERATE));
			result.put("message", "generateAuthnRequestCert() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequestCert() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject generateAuthnRequest(HttpServletRequest request, String id, String idp)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		try {
			String sid = config.getServerSessionidkey() + "=" + request.getSession(true).getId();

			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);

			String xid = SAMLUtil.createSamlId();
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String xtime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			JSONObject sData = new JSONObject();
			sData.put("id", id);
			sData.put("pw", SERVICE_05);
			sData.put("appl", config.getServerApplcode());
			sData.put("sid", sid);
			sData.put("spip", this.serverIP);
			sData.put("xid", xid);
			sData.put("xtm", xtime);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			// 암호키 생성
			SSOSecretKey secKey = cryptoApi.generateSecretKey();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AM", "0",
					id + "," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키,SEED/CBC");

			String encData = cryptoApi.encrypt(secKey, sData.toString());
			String encKey = cryptoApi.encryptPublicKey(idpCert, secKey.getKeyIv());

			// 암호키 분배
			if (SSOConfig.getInstance().isDistCryptoKey()) {
				SSOConfig.getInstance().setDistCryptoKey(false);
				Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AV", "0",
						MetadataRepository.getInstance().getIDPName());
			}

			// 암호키 파기
			secKey.finalize();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AW", "0",
					id + "," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키 분배 후 파기,0 으로 덮어쓰기");

			String responseURL = SAMLUtil.getSPResponseURL(Util.getBaseURL(request), this.serverName);

			// AuthnRequest
			AuthnRequest authnRequest = (AuthnRequest) SAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
			authnRequest.setAssertionConsumerServiceURL(responseURL);
			authnRequest.setDestination(SAMLUtil.getIdpRequestURL(idp));
			authnRequest.setID(xid);
			authnRequest.setProviderName(this.serverName);
			authnRequest.setIssueInstant(issueTime);

			// Issuer
			Issuer issuer = (Issuer) SAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
			issuer.setSPProvidedID(this.serverName);
			issuer.setValue(this.serverName);

			authnRequest.setIssuer(issuer);

			// Subject
			Subject subject = (Subject) SAMLUtil.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

			NameID nameid = (NameID) SAMLUtil.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
			nameid.setFormat(NameID.ENTITY);
			nameid.setValue(id);

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

			// RequestedAuthnContext
			RequestedAuthnContext reqAuthnContext = (RequestedAuthnContext) SAMLUtil.buildXMLObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			reqAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			AuthnContextClassRef classref = (AuthnContextClassRef) SAMLUtil.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			classref.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

			reqAuthnContext.getAuthnContextClassRefs().add(classref);
			authnRequest.setRequestedAuthnContext(reqAuthnContext);

			// Sign
			SPSSODescriptor spDescriptor = MetadataRepository.getInstance().getSPDescriptor(this.serverName);

			if (spDescriptor.isAuthnRequestsSigned()) {
				SSOCryptoApi.getInstance().generateSignedXML(authnRequest);
			}
			else {
				SAMLUtil.checkAndMarshall(authnRequest);
			}

			// AuthnRequest XML String
//			SAMLUtil.checkAndMarshall(authnRequest);
//			Document document2 = authnRequest.getDOM().getOwnerDocument();
//			log.debug("### AuthnRequest XML String:\n" + Util.domToStr(document2, true));

			session.setAttribute("LGCHLG", "L" + authnRequest.getID());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", authnRequest);
			return result;
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateAuthnRequest() CryptoApiException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (SSOException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generateAuthnRequest() SSOException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() SSOException: " + e.getErrorCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_GENERATE));
			result.put("message", "generateAuthnRequest() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject generateAuthnRequestCS(HttpServletRequest request, String idp)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		try {
			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			String eData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

			if (eData.equals("")) {
				log.error("### generateAuthnRequestCS() Parameter Invalid(1)");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_PARAM_INVALID));
				result.put("message", "generateAuthnRequestCS() Parameter Invalid(1)");
				result.put("data", "");
				return result;
			}

			byte[] decData = cryptoApi.decryptSym(eData);
			String strData = new String(decData, "EUC-KR");

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(strData);

			log.debug("### generateAuthnRequestCS() jsonData = " + strData);

			String timeStamp = (String) jsonData.get("time");

			if (timeStamp.length() != 15) {
				log.error("### generateAuthnRequestCS() Parameter Invalid(2)");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_PARAM_INVALID));
				result.put("message", "generateAuthnRequestCS() Parameter Invalid(2)");
				result.put("data", "");
				return result;
			}

			long reqTime = Long.parseLong(timeStamp) + config.getInt("expire.timeout", 10) * 1000;
			long curTime = System.currentTimeMillis();

			if (curTime > reqTime) {
				log.error("### generateAuthnRequestCS() Parameter Expired");
				log.debug("### curTime = " + curTime);
				log.debug("### reqTime = " + reqTime);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_PARAM_INVALID));
				result.put("message", "generateAuthnRequestCS() Parameter Expired");
				result.put("data", "");
				return result;
			}

			String id = (String) jsonData.get("id");
			String relaystate = (String) jsonData.get("relay");

			if (id.equals("")) {
				log.error("### generateAuthnRequestCS() Parameter Invalid(3)");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_PARAM_INVALID));
				result.put("message", "generateAuthnRequestCS() Parameter Invalid(3)");
				result.put("data", "");
				return result;
			}

			String sid = config.getServerSessionidkey() + "=" + request.getSession(true).getId();

			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);

			String xid = SAMLUtil.createSamlId();
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String xtime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			JSONObject sData = new JSONObject();
			sData.put("id", id);
			sData.put("pw", SERVICE_05);
			sData.put("appl", config.getServerApplcode());
			sData.put("sid", sid);
			sData.put("spip", this.serverIP);
			sData.put("xid", xid);
			sData.put("xtm", xtime);


			// 암호키 생성
			SSOSecretKey secKey = cryptoApi.generateSecretKey();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AM", "0",
					id + "," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키,SEED/CBC");

			String encData = cryptoApi.encrypt(secKey, sData.toString());
			String encKey = cryptoApi.encryptPublicKey(idpCert, secKey.getKeyIv());

			// 암호키 분배
			if (SSOConfig.getInstance().isDistCryptoKey()) {
				SSOConfig.getInstance().setDistCryptoKey(false);
				Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AV", "0",
						MetadataRepository.getInstance().getIDPName());
			}

			// 암호키 파기
			secKey.finalize();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AW", "0",
					id + "," + Util.getClientIP(request) + ",로그인 요청 전송정보 암호키 분배 후 파기,0 으로 덮어쓰기");

			String responseURL = SAMLUtil.getSPResponseURL(Util.getBaseURL(request), this.serverName);

			// AuthnRequest
			AuthnRequest authnRequest = (AuthnRequest) SAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
			authnRequest.setAssertionConsumerServiceURL(responseURL);
			authnRequest.setDestination(SAMLUtil.getIdpRequestURL(idp));
			authnRequest.setID(xid);
			authnRequest.setProviderName(this.serverName);
			authnRequest.setIssueInstant(issueTime);

			// Issuer
			Issuer issuer = (Issuer) SAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
			issuer.setSPProvidedID(this.serverName);
			issuer.setValue(this.serverName);

			authnRequest.setIssuer(issuer);

			// Subject
			Subject subject = (Subject) SAMLUtil.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

			NameID nameid = (NameID) SAMLUtil.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
			nameid.setFormat(NameID.ENTITY);
			nameid.setValue(id);

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

			// RequestedAuthnContext
			RequestedAuthnContext reqAuthnContext = (RequestedAuthnContext) SAMLUtil.buildXMLObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			reqAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			AuthnContextClassRef classref = (AuthnContextClassRef) SAMLUtil.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			classref.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

			reqAuthnContext.getAuthnContextClassRefs().add(classref);
			authnRequest.setRequestedAuthnContext(reqAuthnContext);

			// Sign
			SPSSODescriptor spDescriptor = MetadataRepository.getInstance().getSPDescriptor(this.serverName);

			if (spDescriptor.isAuthnRequestsSigned()) {
				SSOCryptoApi.getInstance().generateSignedXML(authnRequest);
			}
			else {
				SAMLUtil.checkAndMarshall(authnRequest);
			}

			// AuthnRequest XML String
//			SAMLUtil.checkAndMarshall(authnRequest);
//			Document document2 = authnRequest.getDOM().getOwnerDocument();
//			log.debug("### AuthnRequest XML String:\n" + Util.domToStr(document2, true));

			session.setAttribute("LGCHLG", "L" + authnRequest.getID());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", authnRequest);
			result.put("relaystate", relaystate);
			return result;
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateAuthnRequestCS() CryptoApiException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequestCS() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (SSOException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generateAuthnRequestCS() SSOException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequestCS() SSOException: " + e.getErrorCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_GENERATE));
			result.put("message", "generateAuthnRequestCS() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequestCS() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject generateAuthnRequest(HttpServletRequest request, String idp)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		try {
			String sid = config.getServerSessionidkey() + "=" + request.getSession(true).getId();

			String idpName = MetadataRepository.getInstance().getIDPName();
			Credential idpCert = CredentialRepository.getCredential(idpName, MStatus.ENC_CERT);

			String xid = SAMLUtil.createSamlId();
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String xtime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			JSONObject sData = new JSONObject();
			sData.put("id", SUBJECT_EMPTY_ID);
			sData.put("appl", config.getServerApplcode());
			sData.put("sid", sid);
			sData.put("spip", this.serverIP);
			sData.put("xid", xid);
			sData.put("xtm", xtime);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			// 암호키 생성
			SSOSecretKey secKey = cryptoApi.generateSecretKey();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AM", "0",
					Util.getClientIP(request) + ",연계 요청 전송정보 암호키,SEED/CBC");

			String encData = cryptoApi.encrypt(secKey, sData.toString());
			String encKey = cryptoApi.encryptPublicKey(idpCert, secKey.getKeyIv());

			// 암호키 분배
			if (SSOConfig.getInstance().isDistCryptoKey()) {
				SSOConfig.getInstance().setDistCryptoKey(false);
				Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AV", "0",
						MetadataRepository.getInstance().getIDPName());
			}

			// 암호키 파기
			secKey.finalize();

			Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AW", "0",
					Util.getClientIP(request) + ",연계 요청 전송정보 암호키 분배 후 파기,0 으로 덮어쓰기");

			String responseURL = SAMLUtil.getSPResponseURL(Util.getBaseURL(request), this.serverName);

			// AuthnRequest
			AuthnRequest authnRequest = (AuthnRequest) SAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
			authnRequest.setAssertionConsumerServiceURL(responseURL);
			authnRequest.setDestination(SAMLUtil.getIdpRequestURL(idp));
			authnRequest.setID(xid);
			authnRequest.setProviderName(this.serverName);
			authnRequest.setIssueInstant(issueTime);

			// Issuer
			Issuer issuer = (Issuer) SAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
			issuer.setSPProvidedID(this.serverName);
			issuer.setValue(this.serverName);

			authnRequest.setIssuer(issuer);

			// Subject
			Subject subject = (Subject) SAMLUtil.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);

			NameID nameid = (NameID) SAMLUtil.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
			nameid.setFormat(NameID.ENTITY);
			nameid.setValue(SUBJECT_EMPTY_ID);

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

			// RequestedAuthnContext
			RequestedAuthnContext reqAuthnContext = (RequestedAuthnContext) SAMLUtil.buildXMLObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			reqAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			AuthnContextClassRef classref = (AuthnContextClassRef) SAMLUtil.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			classref.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
			reqAuthnContext.getAuthnContextClassRefs().add(classref);

			classref = (AuthnContextClassRef) SAMLUtil.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			classref.setAuthnContextClassRef(AuthnContext.X509_AUTHN_CTX);
			reqAuthnContext.getAuthnContextClassRefs().add(classref);

			authnRequest.setRequestedAuthnContext(reqAuthnContext);

			// Sign
			SPSSODescriptor spDescriptor = MetadataRepository.getInstance().getSPDescriptor(this.serverName);

			if (spDescriptor.isAuthnRequestsSigned()) {
				SSOCryptoApi.getInstance().generateSignedXML(authnRequest);
			}
			else {
				SAMLUtil.checkAndMarshall(authnRequest);
			}

			// AuthnRequest XML String
//			SAMLUtil.checkAndMarshall(authnRequest);
//			Document document2 = authnRequest.getDOM().getOwnerDocument();
//			log.debug("### AuthnRequest XML String:\n" + Util.domToStr(document2, true));

			session.setAttribute("LGCHLG", "C" + authnRequest.getID());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", authnRequest);
			return result;
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateAuthnRequest() CryptoApiException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (SSOException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generateAuthnRequest() SSOException: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() SSOException: " + e.getErrorCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_GENERATE));
			result.put("message", "generateAuthnRequest() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateAuthnRequest() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject getConnectCSData(HttpServletRequest request, String attributeKey)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		try {
			String attrVal = (String) session.getAttribute(attributeKey);

			if (attrVal == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_NON_LOGIN));
				result.put("message", "로그인 상태 아님");
				result.put("data", "");
				return result;
			}

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			JSONObject connData = new JSONObject();
			connData.put("time", Util.getDecimalTime());
			connData.put("id", attrVal);
			connData.put("url", request.getRequestURL().toString());

			byte[] encData = cryptoApi.encryptSym(connData.toString().getBytes("EUC-KR"));
			String enc64Data = Util.encode64(encData);

			log.debug("### getConnectCSData() jsonData = " + connData.toString());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", enc64Data);
			return result;
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_GENERATE));
			result.put("message", "getConnectCSData() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### getConnectCSData() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject generateRoleData(HttpServletRequest request, String appl, String redirectUrl)
	{
		JSONObject result = null;

		if (Util.isEmpty(redirectUrl)) {
			log.error("### generateRoleData() redirectUrl is NULL");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_ROLE_ERR_INVALID_PARAMETER));
			result.put("message", "generateRoleData() redirectUrl is NULL");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		if (session == null) {
			log.error("### generateRoleData() session is NULL");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_ROLE_ERR_SESSION_INVALID));
			result.put("message", "generateRoleData() session is NULL");
			result.put("data", "");
			return result;
		}

		String id = (String) session.getAttribute("SSO_ID");

		if (Util.isEmpty(id)) {
			log.error("### generateRoleData() session SSO_ID is NULL");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_ROLE_ERR_SESSION_INVALID));
			result.put("message", "generateRoleData() session SSO_ID is NULL");
			result.put("data", "");
			return result;
		}

		DateTime issueTime = new DateTime(DateTimeZone.UTC);
		String time = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

		try {
			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();
			JSONObject jsonData = new JSONObject();

			jsonData.put("id", id);
			jsonData.put("time", time);
			jsonData.put("appl", appl);
			jsonData.put("url", redirectUrl);

			byte[] encData = cryptoApi.encryptSym(jsonData.toString().getBytes("UTF-8"));
			String enc64Data = Util.encode64(encData);

			if (Util.isEmpty(enc64Data)) {
				log.error("### generateRoleData() enc64Data is NULL");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.API_ROLE_ERR_INVALID_PARAMETER));
				result.put("message", "generateRoleData() enc64Data is NULL");
				result.put("data", "");
				return result;
			}

			log.debug("### generateRoleData() jsonData = " + jsonData.toString());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", enc64Data);
			return result;
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_ROLE_ERR_EXCEPTION));
			result.put("message", "generateRoleData() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### generateRoleData() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject receiveRoleData(HttpServletRequest request)
	{
		JSONObject result = null;
		String ED = request.getParameter("ED") == null ? "" : (String) request.getParameter("ED");

		if (Util.isEmpty(ED)) {
			log.error("### receiveRoleData() Parameter EncData is Null: ");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_ROLE_ERR_INVALID_PARAMETER));
			result.put("message", "Parameter ED Empty");
			result.put("data", "");
			return result;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(URLDecoder.decode(ED, "UTF-8")));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String code = (String) jsonData.get("code");
			String message = (String) jsonData.get("message");

			if (Integer.parseInt(code) != MStatus.SUCCESS) {
				log.error("### receiveRoleData() " + code + ", " + message);

				result = new JSONObject();
				result.put("code", String.valueOf(code));
				result.put("message", message);
				result.put("data", "");
				return result;
			}

			String jsonStringRole = (String) jsonData.get("data");

			if (Util.isEmpty(jsonStringRole)) {
				log.error("### receiveRoleData() Role Data is Null");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.API_ROLE_ERR_ROLE_EMPTY));
				result.put("message", "Role Data is Null");
				result.put("data", "");
				return result;
			}

			JSONObject jsonRole = (JSONObject) parser.parse(jsonStringRole);
			HttpSession session = request.getSession(false);

			if (session == null) {
				log.error("### receiveRoleData() Session is Null");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.API_ROLE_ERR_SESSION_INVALID));
				result.put("message", "receiveRoleData() session NULL");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty((String) session.getAttribute("SSO_ID"))) {
				log.error("### receiveRoleData() Session SSO_ID is Null");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.API_ROLE_ERR_SESSION_INVALID));
				result.put("message", "receiveRoleData() session SSO_ID is NULL");
				result.put("data", "");
				return result;
			}

			session.setAttribute(SESSION_ROLE, jsonRole.toString());

			log.debug("### receiveRoleData() jsonRole = " + jsonRole.toJSONString());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
			return result;
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.API_ROLE_ERR_EXCEPTION));
			result.put("message", "receiveRoleData() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### receiveRoleData() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject getLauncherXPData(HttpServletRequest request)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		try {
			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			String id = (String) session.getAttribute("SSO_ID");

			JSONObject plainJson = new JSONObject();
			plainJson.put("id", id);
			plainJson.put("T", "1");

			byte[] encryptJsonByte = cryptoApi.encryptSym(plainJson.toString().getBytes());
			String encryptData = SSOCryptoApi.encode64(encryptJsonByte);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encryptData);
			return result;
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "getLauncherXPData() CryptoApiException: " + e.getMessage());
			result.put("data", "");

			log.debug("### getLauncherXPData() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_GENERATE));
			result.put("message", "getLauncherXPData() Exception: " + e.getMessage());
			result.put("data", "");

			log.debug("### getLauncherXPData() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject readResponse(HttpServletRequest request, HttpServletResponse response, Map<String, String> sessionAttrMap)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();
		HttpSession session = request.getSession(true);

		String sesChallenge = (String) session.getAttribute("LGCHLG");
		session.removeAttribute("LGCHLG");

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		result = getMessageContext(request, response);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		MessageContext messageContext = (MessageContext) result.get("data");

		if (messageContext == null) {
			log.error("### MessageContext Null");

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "MessageContext Null");
			result.put("data", "");
			return result;
		}

		Response samlResponse = (Response) messageContext.getInboundMessage();

		String rcvChallenge = samlResponse.getInResponseTo();
		String reqType = "";

		if (!Util.isEmpty(sesChallenge) && !Util.isEmpty(rcvChallenge)) {
			reqType = sesChallenge.substring(0, 1);
			String sndChallenge = sesChallenge.substring(1);

			if (!sndChallenge.equals(rcvChallenge)) {
				if (reqType.equals("L")) {
					Util.setAuditInfo(config.getServerName(), "AG", "1", "인증정보 패킷 재사용");
				}
				else {
					Util.setAuditInfo(config.getServerName(), "AH", "1", "인증정보 패킷 재사용");
				}

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "인증정보 패킷 재사용");
				result.put("data", "");
				return result;
			}
		}
		else {
			Util.setAuditInfo(config.getServerName(), "AG", "1", "인증정보 패킷 재사용");

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "인증정보 패킷 재사용");
			result.put("data", "");
			return result;
		}

		result = getSessionAttribute(samlResponse, sessionAttrMap, reqType);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		Map<String, Object> resultMap = (Map<String, Object>) result.get("data");

		if (resultMap.isEmpty()) {
			log.error("### MessageContext Null");

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "MessageContext Null");
			result.put("data", "");
			return result;
		}

		Iterator<?> iterator = resultMap.keySet().iterator();

		while (iterator.hasNext()) {
			Object o = iterator.next();
			session.setAttribute((String) o, resultMap.get(o));
		}

		result = null;
		result = new JSONObject();
		result.put("code", String.valueOf(MStatus.SUCCESS));
		result.put("message", "SUCCESS");
		result.put("data", "");
		return result;
	}

	public JSONObject getMessageContext(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = new JSONObject();

		MessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		messageContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response, true));
		SAMLMessageDecoder samlMessageDecoder = new HTTPPostDecoder();

		try {
			samlMessageDecoder.decode(messageContext);

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", messageContext);
		}
		catch (Exception e) {
			log.error("### ServiceProvider.getMessageContext() Exception: " + e.toString());

			result.put("code", String.valueOf(MStatus.AUTH_MESSAGE_DECODE));
			result.put("message", "ServiceProvider.getMessageContext() Exception: " + e.getMessage());
			result.put("data", messageContext);
		}

		return result;
	}

	public JSONObject getSessionAttribute(Response samlResponse, Map<String, String> sessionAttrMap, String reqType)
	{
		JSONObject result = null;

		Map<String, Object> resultMap = new HashMap<String, Object>();

		try {
			log.debug("### Response XML:\n" + Util.domToStr(samlResponse.getDOM().getOwnerDocument(), true));

			Assertion assertion;

			if (!samlResponse.getAssertions().isEmpty()) {
				assertion = samlResponse.getAssertions().get(0);
			}
			else if (!samlResponse.getEncryptedAssertions().isEmpty()) {
				EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
				assertion = SSOCryptoApi.getInstance().getDecryptAssertion(encryptedAssertion);
			}
			else {
				log.error("### Assertion Get Failure");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ASSERT_GET));
				result.put("message", "Assertion Get Failure");
				result.put("data","");
				return result;
			}

			result = checkValidationAssertion(assertion);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			log.debug("### Assertion XML:\n" + Util.domToStr(assertion.getDOM().getOwnerDocument(), true));

			boolean isVerified = true;

			if (assertion.isSigned()) {
				isVerified = SSOCryptoApi.getInstance().verifySignature(assertion);

				log.debug("### Assertion Verify = " + isVerified);
			}

			if (isVerified == false) {
				log.error("### Assertion Verify Failure");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ASSERT_VERIFY));
				result.put("message", "Assertion Verify Failure");
				result.put("data","");
				return result;
			}

			// check Response ID, IssueTime
			if (!samlResponse.getID().equals(assertion.getID())) {
				log.error("### Saml Response ID Invalid");

				if (reqType.equals("L")) {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AG", "1", "인증정보 패킷 재사용");
				}
				else {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AH", "1", "인증정보 패킷 재사용");
				}

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ASSERT_ID_INVALID));
				result.put("message", "Saml Response ID Invalid");
				result.put("data","");
				return result;
			}

			if (!samlResponse.getIssueInstant().equals(assertion.getIssueInstant())) {
				log.error("### Saml Response IssueInstant Invalid");

				if (reqType.equals("L")) {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AG", "1", "인증정보 패킷 재사용");
				}
				else {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AH", "1", "인증정보 패킷 재사용");
				}

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ASSERT_ISSUE_TIME_INVALID));
				result.put("message", "Saml Response IssueInstant Invalid");
				result.put("data","");
				return result;
			}

			// get Data
			SSOToken token = null;
			String idpSessionID = "";
			String xid = "";
			DateTime issueTime = null;

			List<Attribute> attributes = (assertion.getAttributeStatements().get(0)).getAttributes();

			for (int i = 0; i < attributes.size(); i++) {
				Attribute attribute = (Attribute) attributes.get(i);

				if ("AUTHN_INFO".equalsIgnoreCase(attribute.getName())) {
					String encData = ((XSString) attribute.getAttributeValues().get(0)).getValue();
					String jsonStr = new String(Util.decode64(encData), "UTF-8");

					JSONParser parser = new JSONParser();
					JSONObject jsonData = (JSONObject) parser.parse(jsonStr);

					idpSessionID = (String) jsonData.get("idpsession");

					StringBuilder sbToken = new StringBuilder((String) jsonData.get("token"));
					token = new SSOToken(sbToken);

					xid = (String) jsonData.get("xid");

					String xtm = (String) jsonData.get("xtm");
					DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZoneUTC();
					issueTime = format.parseDateTime(xtm);
				}
			}

			// check Assertion ID, IssueTime
			if (!assertion.getID().equals(xid)) {
				log.error("### Saml Assertion ID Invalid");

				if (reqType.equals("L")) {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AG", "1", "인증정보 패킷 재사용");
				}
				else {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AH", "1", "인증정보 패킷 재사용");
				}

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ASSERT_ID_INVALID));
				result.put("message", "Saml Assertion ID Invalid");
				result.put("data","");
				return result;
			}

			if (!assertion.getIssueInstant().equals(issueTime)) {
				log.error("### Saml Response Assertion Invalid");

				if (reqType.equals("L")) {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AG", "1", "인증정보 패킷 재사용");
				}
				else {
					Util.setAuditInfo(SSOConfig.getInstance().getServerName(), "AH", "1", "인증정보 패킷 재사용");
				}

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.ASSERT_ISSUE_TIME_INVALID));
				result.put("message", "Saml Assertion IssueInstant Invalid");
				result.put("data","");
				return result;
			}

			// make Result
			Iterator<?> iterator = sessionAttrMap.keySet().iterator();
			while (iterator.hasNext()) {
				String key = (String) iterator.next();
				resultMap.put(sessionAttrMap.get(key), token.getProperty(key));
			}

			resultMap.put("IDP_Session", idpSessionID);
			resultMap.put(SESSION_TOKEN, token.toString());
			resultMap.put("SSO_SESSTIME", System.currentTimeMillis());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data",resultMap);
		}
		catch (Exception e) {
			resultMap.clear();
			log.error("### getSessionAttribute() Exception: " + e.toString());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ASSERT_GET));
			result.put("message", "getSessionAttribute() Exception: " + e.getMessage());
			result.put("data","");
		}

		return result;
	}

	private JSONObject checkValidationAssertion(Assertion assertion)
	{
		JSONObject result = new JSONObject();

		DateTime dateTime = new DateTime(DateTimeZone.UTC).minusMinutes(SSOConfig.getInstance().getRequestTimeout());

		if (dateTime.compareTo(assertion.getIssueInstant()) > 0) {
			log.error("### Assertion Timeout");

			result.put("code", String.valueOf(MStatus.ASSERT_TIMEOUT));
			result.put("message", "Assertion Timeout");
			result.put("data","");
			return result;
		}

		result.put("code", String.valueOf(MStatus.SUCCESS));
		result.put("message", "SUCCESS");
		result.put("data","");
		return result;
	}

	// Mobile
	public JSONObject sendHttpRequest(String requestUrl, String param)
	{
		JSONObject result = new JSONObject();

		try {
			if (requestUrl.indexOf("https") >= 0) {
				TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
				{
					public java.security.cert.X509Certificate[] getAcceptedIssuers()
					{
						return null;
					}

					public void checkClientTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}

					public void checkServerTrusted(java.security.cert.X509Certificate[] arg0, String arg1) throws CertificateException
					{
					}
				} };

				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
				HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
				{
					public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession)
					{
						return true;
					}
				});
			}

			URL url = new URL(requestUrl);

			HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
			urlConn.setRequestMethod("POST");
			urlConn.setDoOutput(true);
			urlConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

			OutputStream stream = urlConn.getOutputStream();
			stream.write(param.getBytes("UTF-8"));
			stream.flush();
			stream.close();

			int rcode = urlConn.getResponseCode();
			if (rcode != 200) {
				result.put("code", String.valueOf(6001));
				result.put("message", "SP: http response error " + rcode);
				result.put("data", "");
				return result;
			}

			BufferedReader br = new BufferedReader(new InputStreamReader(urlConn.getInputStream(), "UTF-8"));

			StringBuffer strBuffer = new StringBuffer();
			String strLine = "";

			while ((strLine = br.readLine()) != null) {
				strBuffer.append(strLine);
			}

			br.close();
			urlConn.disconnect();

			JSONParser parser = new JSONParser();
			JSONObject jsonResponse = (JSONObject) parser.parse(strBuffer.toString());

			result.put("code", jsonResponse.get("code"));
			result.put("message", jsonResponse.get("message"));
			result.put("data", jsonResponse.get("data"));
		}
		catch (Exception e) {
			result.put("code", String.valueOf(6002));
			result.put("message", "SP: sendHttpRequest Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public static JSONObject parseDeviceConfig(File file)
	{
		JSONObject result = new JSONObject();

		if (file == null || !file.exists()) {
			result.put("code", String.valueOf(6003));
			result.put("message", "SP: Device Config File is not exist");
			result.put("date", "");
			return result;
		}

		try {
			FileInputStream inputStream = new FileInputStream(file);

			StringBuffer buff = new StringBuffer();

			int k;
			while ((k = inputStream.read()) != -1) {
				buff.append((char) k);
			}

			String[] configLines = buff.toString().split("\r\n");
			String mode = "";

			JSONObject dataJson = new JSONObject();
			JSONArray appArray = new JSONArray();

			for (int i = 0; i < configLines.length; i++) {
				int index = configLines[i].indexOf("app=");

				if (index == 0) {
					appArray.add(configLines[i].substring(index + 4).trim());
				}
				else {
					int idx = configLines[i].indexOf("=");
					if (idx > 0)
						dataJson.put(configLines[i].substring(0, idx).trim(), configLines[i].substring(idx + 1).trim());
				}
			}

			dataJson.put("APP", appArray);

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", dataJson);
		}
		catch (Exception e) {
			result.put("code", String.valueOf(6004));
			result.put("message", "SP: parseDeviceConfig Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject createChallenge(String id, String device, String logstr)
	{
		JSONObject result = null;

		try {
			if (Util.isEmpty(id) || Util.isEmpty(device)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6006));
				result.put("message", "SP " + logstr + ": Invalid Parameter");
				result.put("data", "");
				return result;
			}

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			String mapKey = id + SEPARATOR + device;
			String challenge = new String(Hex.encode(crypto.createRandom(16).getBytes()));
			String timeStamp = new DecimalFormat("000000000000000").format(System.currentTimeMillis());

			if (SSOConfig.getInstance().isChallengeVerify()) {
				SyncMonitor.startMonitor();
				SyncManager.getInstance().setChallenge(mapKey, challenge + SEPARATOR + timeStamp);
			}

			log.debug("### SP " + logstr + " Challenge: " + mapKey + " = " + challenge + SEPARATOR + timeStamp);

			JSONObject retJson = new JSONObject();
			retJson.put("time", timeStamp + SEPARATOR + challenge);

			byte[] sendByte = crypto.encryptSym(retJson.toJSONString().getBytes());
			String sendData = Util.encode64(sendByte);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "T");
			result.put("data", sendData);
			return result;
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(6007));
			result.put("message", "SP " + logstr + " Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public JSONObject checkChallenge(String id, String device, String value, String logstr)
	{
		JSONObject result = null;

		try {
			if (Util.isEmpty(id) || Util.isEmpty(device) || Util.isEmpty(value)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6008));
				result.put("message", "SP " + logstr + ": Invalid Parameter");
				result.put("data", "");
				return result;
			}

			String rcvTime = null;
			String rcvChlg = null;
			int idx = -1;

			if ((idx = value.indexOf(SEPARATOR)) >= 0) {
				rcvTime = value.substring(0, idx);
				rcvChlg = value.substring(idx + 3);
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(6009));
				result.put("message", "SP " + logstr + ": Invalid Time Data(1)");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(rcvTime) || Util.isEmpty(rcvChlg)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6010));
				result.put("message", "SP " + logstr + ": Invalid Time Data(2)");
				result.put("data", "");
				return result;
			}

			if (rcvTime.length() != 15) {
				result = new JSONObject();
				result.put("code", String.valueOf(6011));
				result.put("message", "SP " + logstr + ": Invalid Time Data(3)");
				result.put("data", "");
				return result;
			}

			long reqTime = Long.parseLong(rcvTime) + (SSOConfig.getInstance().getInt("smart.timeout", 5) * 1000);  // 5 sec
			long curTime = System.currentTimeMillis();

			if (curTime > reqTime) {
				result = new JSONObject();
				result.put("code", String.valueOf(6012));
				result.put("message", "SP " + logstr + ": Timeout Data");
				result.put("data", "");
				return result;
			}

			if (SSOConfig.getInstance().isChallengeVerify()) {
				String rcvKey = id + SEPARATOR + device;
				String mapVal = (String) SyncManager.getInstance().getChallengeMap().get(rcvKey);
				String mapClg;

				if (Util.isEmpty(mapVal)) {
					result = new JSONObject();
					result.put("code", String.valueOf(6013));
					result.put("message", "SP " + logstr + ": Not Match Challenge(1)");
					result.put("data", "");
					return result;
				}

				idx = -1;
				if ((idx = mapVal.indexOf(SEPARATOR)) >= 0) {
					mapClg = mapVal.substring(0, idx);
				}
				else {
					mapClg = mapVal;
				}

				SyncMonitor.startMonitor();
				SyncManager.getInstance().removeChallenge(rcvKey);

				if (!mapClg.equals(rcvChlg)) {
					result = new JSONObject();
					result.put("code", String.valueOf(6014));
					result.put("message", "SP " + logstr + ": Not Match Challenge(2)");
					result.put("data", "");
					return result;
				}
			}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
			return result;
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(6015));
			result.put("message", "SP " + logstr + " Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public JSONObject getSmartConfig()
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		try {
			String confPath = config.getHomePath("config/dsdevice.conf");
			File configFile = new File(confPath);

			result = parseDeviceConfig(configFile);

			if (!String.valueOf(result.get("code")).equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			JSONObject jsonData = (JSONObject) result.get("data");

			byte[] encByte = SSOCryptoApi.getInstance().encryptSym(jsonData.toString().getBytes());
			String encData = Util.encode64(encByte);

			log.debug("### Device Config: \n" + jsonData.toString());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encData);
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(6005));
			result.put("message", "SP: getSmartConfig() Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e);
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject smartLogin(String url, String encData)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String proc = (String) jsonData.get("proc");

			if (proc != null && proc.equals("T")) {
				String id = (String) jsonData.get("id");
				String device = (String) jsonData.get("device");

				return createChallenge(id, device, "login");
			}

			// Check Mobile Data
			String time = (String) jsonData.get("time");
			String id = (String) jsonData.get("id");
			String pw = (String) jsonData.get("pw");
			String device = (String) jsonData.get("device");

			if (Util.isEmpty(pw)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6016));
				result.put("message", "SP login: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			result = checkChallenge(id, device, time, "login");

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			// Request to IDP
			String tid = Util.createTransferId();

			jsonData.remove("time");
			jsonData.put("proc", "L");
			jsonData.put("servername", config.getServerName());
			jsonData.put("applcode", config.getServerApplcode());
			jsonData.put("xid", tid);

			String encParam = crypto.encryptJsonObject(jsonData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encParam, "UTF-8"));

			result = null;
			result = sendHttpRequest(url, param.toString());

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			JSONObject jsonRet = crypto.decryptJsonObject((String) result.get("data"));

			JSONObject returnJson = new JSONObject();
			returnJson.put("id", (String) jsonRet.get("id"));
			returnJson.put("authcode", (String) jsonRet.get("authcode"));
			returnJson.put("token", (String) jsonRet.get("token"));

			byte[] encRetByte = crypto.encryptSym(returnJson.toString().getBytes());
			String encRetData = Util.encode64(encRetByte);

			result.put("data", encRetData);
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6017));
			result.put("message", "SP login Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public JSONObject smartConnect(String url, String encData)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String proc = (String) jsonData.get("proc");

			if (proc != null && proc.equals("T")) {
				String id = (String) jsonData.get("id");
				String device = (String) jsonData.get("device");

				return createChallenge(id, device, "connect");
			}

			// Check Mobile Data
			String time = (String) jsonData.get("time");
			String id = (String) jsonData.get("id");
			String authcode = (String) jsonData.get("authcode");
			String device = (String) jsonData.get("device");

			if (Util.isEmpty(authcode)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6018));
				result.put("message", "SP connect: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			result = checkChallenge(id, device, time, "connect");

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			// Request to IDP
			String tid = Util.createTransferId();

			jsonData.remove("time");
			jsonData.put("proc", "C");
			jsonData.put("servername", config.getServerName());
			jsonData.put("applcode", config.getServerApplcode());
			jsonData.put("xid", tid);

			String encParam = crypto.encryptJsonObject(jsonData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encParam, "UTF-8"));

			result = null;
			result = sendHttpRequest(url, param.toString());

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			JSONObject jsonRet = crypto.decryptJsonObject((String) result.get("data"));

			JSONObject returnJson = new JSONObject();
			returnJson.put("id", (String) jsonRet.get("id"));
			returnJson.put("authcode", (String) jsonRet.get("authcode"));
			returnJson.put("token", (String) jsonRet.get("token"));

			byte[] encRetByte = crypto.encryptSym(returnJson.toString().getBytes());
			String encRetData = Util.encode64(encRetByte);

			result.put("data", encRetData);
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6019));
			result.put("message", "SP connect Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public JSONObject smartLogout(String url, String encData)
	{
		JSONObject result = null;

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String proc = (String) jsonData.get("proc");

			if (proc != null && proc.equals("T")) {
				String id = (String) jsonData.get("id");
				String device = (String) jsonData.get("device");

				return createChallenge(id, device, "logout");
			}

			// Check Mobile Data
			String time = (String) jsonData.get("time");
			String id = (String) jsonData.get("id");
			String authcode = (String) jsonData.get("authcode");
			String device = (String) jsonData.get("device");

			if (Util.isEmpty(authcode)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6020));
				result.put("message", "SP logout: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			result = checkChallenge(id, device, time, "logout");

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			// Request to IDP
			SSOConfig config = SSOConfig.getInstance();
			String tid = Util.createTransferId();

			jsonData.remove("time");
			jsonData.put("proc", "O");
			jsonData.put("xid", tid);

			String encParam = crypto.encryptJsonObject(jsonData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encParam, "UTF-8"));

			result = null;
			result = sendHttpRequest(url, param.toString());

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6021));
			result.put("message", "SP logout Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e);
			e.printStackTrace();
		}

		return result;
	}

	// App to Web
	public JSONObject smartRequestConnectEx(HttpServletRequest request, String encData)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String proc = (String) jsonData.get("proc");

			if (proc != null && proc.equals("T")) {
				String id = (String) jsonData.get("id");
				String device = (String) jsonData.get("device");

				return createChallenge(id, device, "connectEx");
			}

			// Check Mobile Data
			String time = (String) jsonData.get("time");
			String id = (String) jsonData.get("id");
			String authcode = (String) jsonData.get("authcode");
			String device = (String) jsonData.get("device");

			if (Util.isEmpty(authcode)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6022));
				result.put("message", "SP connectEx: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			result = checkChallenge(id, device, time, "connectEx");

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			// Request to IDP
			String responseurl = (String) request.getAttribute("responseurl");
			String relay = request.getAttribute("relaystate") == null ? "" : (String) request.getAttribute("relaystate");
			String sid = config.getServerSessionidkey() + "=" + request.getSession(true).getId();
			String tid = Util.createTransferId();

			JSONObject reqData = new JSONObject();
			reqData.put("id", id);
			reqData.put("device", device);
			reqData.put("authcode", authcode);
			reqData.put("appl", config.getServerApplcode());
			reqData.put("sid", sid);
			reqData.put("spip", this.serverIP);
			reqData.put("relay", relay);
			reqData.put("resurl", responseurl);
			reqData.put("xid", tid);

			String returnData = SSOCryptoApi.getInstance().encryptJsonObject(reqData);

			// AuthnRequest JSON String
			log.debug("### AuthnRequest:\n" + reqData.toString());

			session.setAttribute("LGCHLG", "C" + tid);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", returnData);
		}
		catch (CryptoApiException e) {
			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "SP connectExM CryptoApiException: " + e.getMessage());
			result.put("data", "");

			log.error("### smartRequestConnectEx() CryptoApiException: " + e.getCode() + ", " + e.getMessage());
			e.printStackTrace();
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(6023));
			result.put("message", "SP connectExM Exception: " + e.getMessage());
			result.put("data", "");

			log.error("### smartRequestConnectEx() Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	// App to Web Response
	public JSONObject getResponseData(HttpServletRequest request, Map sessionAttrMap)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(true);

		String sesChallenge = (String) session.getAttribute("LGCHLG");
		String reqType = "";
		String sndChallenge = "";

		session.removeAttribute("LGCHLG");

		if (!Util.isEmpty(sesChallenge)) {
			reqType = sesChallenge.substring(0, 1);
			sndChallenge = sesChallenge.substring(1);
		}
		else {
			Util.setAuditInfo(config.getServerName(), "AG", "1", "인증정보 패킷 재사용");

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6024));
			result.put("message", "SP: Session Challenge Empty");
			result.put("data", "");
			return result;
		}

		try {
			String responseData = request.getParameter("ResponseData");

			// Decrypt Data
			JSONObject jsonData = SSOCryptoApi.getInstance().decryptJsonObject(responseData);

			String rcvChallenge = (String) jsonData.get("auid");

			if (!Util.isEmpty(rcvChallenge)) {
				if (!sndChallenge.equals(rcvChallenge)) {
					if (reqType.equals("L")) {
						Util.setAuditInfo(config.getServerName(), "AG", "1", "인증정보 패킷 재사용");
					}
					else {
						Util.setAuditInfo(config.getServerName(), "AH", "1", "인증정보 패킷 재사용");
					}

					result = null;
					result = new JSONObject();
					result.put("code", String.valueOf(6025));
					result.put("message", "SP: Invalid Challenge Data");
					result.put("data", "");
					return result;
				}
			}
			else {
				Util.setAuditInfo(config.getServerName(), "AG", "1", "인증정보 패킷 재사용");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(6026));
				result.put("message", "SP: Recieve Challenge Empty");
				result.put("data", "");
				return result;
			}

			String rcvToken = (String) jsonData.get("token");
			SSOToken token = new SSOToken(rcvToken);
			session.setAttribute(SESSION_TOKEN, rcvToken);

			Iterator iter = sessionAttrMap.keySet().iterator();
			while (iter.hasNext()) {
				Object obj = iter.next();
				session.setAttribute((String) sessionAttrMap.get(obj), token.getProperty((String) obj));
			}

			String rcvRelayState = (String) jsonData.get("relay");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", rcvRelayState);
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(6027));
			result.put("message", "SP: getResponseData() Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public JSONObject checkDupLogin(String uid, String uip, String ubr)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			if (Util.isEmpty(uid) || Util.isEmpty(uip) || Util.isEmpty(ubr)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6028));
				result.put("message", "SP: Parameter Empty");
				result.put("data", "");
				return result;
			}

			// Request Data
			String tid = Util.createTransferId();

			JSONObject jsonData = new JSONObject();
			jsonData.put("id", uid);
			jsonData.put("ip", uid);
			jsonData.put("br", uid);
			jsonData.put("xid", tid);

			String encParam = crypto.encryptJsonObject(jsonData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encParam, "UTF-8"));

			// Request URL
			String checkUrl = config.getCheckDupLoginUrl();

			if (Util.isEmpty(checkUrl)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6029));
				result.put("message", "SP: Target URL Empty");
				result.put("data", "");
				return result;
			}

			// Request to IDP
			result = sendHttpRequest(checkUrl, param.toString());
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6030));
			result.put("message", "SP checkDupLogin Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public JSONObject getCsConfig()
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		try {
			String confPath = config.getHomePath("config/dsmpsapi.conf");
			File configFile = new File(confPath);

			result = parseCsConfig(configFile);

			if (!String.valueOf(result.get("code")).equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			JSONObject jsonData = (JSONObject) result.get("data");

			byte[] encByte = SSOCryptoApi.getInstance().encryptSym(jsonData.toString().getBytes("EUC-KR"));
			String encData = Util.encode64(encByte);

			log.debug("### C/S Config: \n" + jsonData.toString());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encData);
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(6005));
			result.put("message", "SP: getCsConfig() Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e);
			e.printStackTrace();
		}

		return result;
	}

	public static JSONObject parseCsConfig(File file)
	{
		JSONObject result = new JSONObject();

		if (file == null || !file.exists()) {
			result.put("code", String.valueOf(6003));
			result.put("message", "SP: C/S Config File is not exist");
			result.put("date", "");
			return result;
		}

		try {
			FileInputStream inputStream = new FileInputStream(file);
			InputStreamReader reader = new InputStreamReader(inputStream, "UTF-8");
			BufferedReader in = new BufferedReader(reader);

			StringBuffer buff = new StringBuffer();

			int k;
			while ((k = in.read()) != -1) {
				buff.append((char) k);
			}

			String[] configLines = buff.toString().split("\r\n");
			String mode = "";

			JSONObject dataJson = new JSONObject();
			JSONArray connectArray = new JSONArray();

			for (int i = 0; i < configLines.length; i++) {
				int idx = configLines[i].indexOf("=");

				if (idx > 0) {
					String key = configLines[i].substring(0, idx).trim();
					String value = configLines[i].substring(idx + 1).trim();

					if (key.equalsIgnoreCase("connect")) {
						JSONObject connectJson = parseCsConnect(value);

						if (connectJson != null) {
							connectArray.add(connectJson);
						}
					}
					else {
						dataJson.put(key, value);
					}
				}
			}

			if (connectArray.size() > 0) {
				dataJson.put("connect", connectArray);
			}

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", dataJson);
		}
		catch (Exception e) {
			result.put("code", String.valueOf(6004));
			result.put("message", "SP: parseCsConfig Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public static JSONObject parseCsConnect(String value)
	{
		JSONObject result = new JSONObject();

		if (Util.isEmpty(value)) {
			return null;
		}

		try {
			String[] arrValue = value.split(",");

			if (arrValue.length != 5) {
				log.error("### SP: parseCsConnect: Invalid data");
				return null;
			}

			//String urlIcon = SSOConfig.getInstance().getSsoHomepath() + "/plugins/icon/" + arrValue[3];
			//String strIcon = new String(Base64.encode(FileUtil.read(SSOConfig.getInstance().getSsoHomepath() + "/plugins/icon/" + arrValue[3])));

			result.put("name", arrValue[0]);
			result.put("role", arrValue[1]);
			result.put("type", arrValue[2]);
			result.put("icon", arrValue[3]);
			result.put("url", arrValue[4]);
		}
		catch (Exception e) {
			e.printStackTrace();
			log.error("### SP: parseCsConnect Exception: " + e.getMessage());
			return null;
		}

		return result;
	}

	public JSONObject csLogin(String url, String encData)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String proc = (String) jsonData.get("proc");

			if (proc != null && proc.equals("T")) {
				String id = (String) jsonData.get("id");
				String device = (String) jsonData.get("device");

				return createChallenge(id, device, "login");
			}

			// Check C/S Data
			String time = (String) jsonData.get("time");
			String id = (String) jsonData.get("id");
			String pw = (String) jsonData.get("pw");
			String device = (String) jsonData.get("device");

			if (Util.isEmpty(pw)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6016));
				result.put("message", "SP login: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			result = checkChallenge(id, device, time, "login");

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			/*** 주택금융공사
			// Check OTP
			String otp = (String) jsonData.get("otp");

			// Check First Login
			result = null;
			result = UserService.checkFirstLogin(id);

			if (Integer.parseInt((String) result.get("code")) != 0) {
				return result;
			}
			else {
				String return_data = (String) result.get("data");
				if (return_data.equals("0")) {
				    // First Login
					result = new JSONObject();
					result.put("code", String.valueOf(6100));
					result.put("message", "SP login: Fisrt Login");
					result.put("data", "");
					return result;
				}
			}
			***/

			// Request to IDP
			String tid = Util.createTransferId();

			jsonData.remove("time");
			jsonData.put("proc", "L");
			jsonData.put("servername", config.getServerName());
			jsonData.put("applcode", config.getServerApplcode());
			jsonData.put("br", "CS");
			jsonData.put("xid", tid);

			String encParam = crypto.encryptJsonObject(jsonData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encParam, "UTF-8"));

			result = null;
			result = sendHttpRequest(url, param.toString());

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			JSONObject jsonRet = crypto.decryptJsonObject((String) result.get("data"));

			JSONObject returnJson = new JSONObject();
			returnJson.put("id", (String) jsonRet.get("id"));
			returnJson.put("token", (String) jsonRet.get("token"));

			byte[] encRetByte = crypto.encryptSym(returnJson.toString().getBytes("EUC-KR"));
			String encRetData = Util.encode64(encRetByte);

			result.put("data", encRetData);
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6017));
			result.put("message", "SP login Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public JSONObject csLogin2FA(String url, String encData)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### Authentication Inactivated Status");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "Authentication Inactivated Status");
			result.put("data", "");
			return result;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String proc = (String) jsonData.get("proc");

			if (proc != null && proc.equals("T")) {
				String id = (String) jsonData.get("id");
				String device = (String) jsonData.get("device");

				return createChallenge(id, device, "login");
			}

			// Check C/S Data
			String time = (String) jsonData.get("time");
			String id = (String) jsonData.get("id");
			String pw = "";
			String device = (String) jsonData.get("device");
			String authstep =  (String) jsonData.get("authstep");

			if (Util.isEmpty(authstep)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6016));
				result.put("message", "SP login: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			if (authstep.equals("1st")) {
				pw = (String) jsonData.get("pw");
			}
			else if (authstep.equals("2nd")) {
				pw = SERVICE_05;
			}
			else {
				pw = "";
			}

			if (Util.isEmpty(pw)) {
				result = new JSONObject();
				result.put("code", String.valueOf(6016));
				result.put("message", "SP login: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			result = checkChallenge(id, device, time, "login");

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			// Request to IDP
			String tid = Util.createTransferId();

			jsonData.remove("time");
			jsonData.put("proc", "L");
			jsonData.put("servername", config.getServerName());
			jsonData.put("applcode", config.getServerApplcode());
			jsonData.put("br", "CS");
			jsonData.put("xid", tid);

			if (authstep.equals("2nd")) {
				jsonData.put("pw", SERVICE_05);
			}

			String encParam = crypto.encryptJsonObject(jsonData);

			StringBuffer param = new StringBuffer();
			param.append("ED=").append(URLEncoder.encode(encParam, "UTF-8"));

			result = null;
			result = sendHttpRequest(url, param.toString());

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				return result;
			}

			JSONObject jsonRet = crypto.decryptJsonObject((String) result.get("data"));

			JSONObject returnJson = new JSONObject();
			returnJson.put("id", (String) jsonRet.get("id"));
			returnJson.put("token", (String) jsonRet.get("token"));

			byte[] encRetByte = crypto.encryptSym(returnJson.toString().getBytes("EUC-KR"));
			String encRetData = Util.encode64(encRetByte);

			result.put("data", encRetData);
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6017));
			result.put("message", "SP login Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}
}