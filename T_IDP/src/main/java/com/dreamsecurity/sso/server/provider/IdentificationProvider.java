package com.dreamsecurity.sso.server.provider;

import java.net.URL;
import java.net.URLDecoder;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.w3c.dom.Document;

import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.lib.dss.cn.binding.BasicSAMLMessageContext;
import com.dreamsecurity.sso.lib.dss.cn.binding.decoding.SAMLMessageDecoder;
import com.dreamsecurity.sso.lib.dss.s2.binding.decoding.HTTPPostDecoder;
import com.dreamsecurity.sso.lib.dss.s2.binding.decoding.HTTPRedirectDeflateDecoder;
import com.dreamsecurity.sso.lib.dss.s2.core.Assertion;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnContext;
import com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest;
import com.dreamsecurity.sso.lib.dss.s2.core.EncryptedAssertion;
import com.dreamsecurity.sso.lib.dss.s2.core.NameID;
import com.dreamsecurity.sso.lib.dss.s2.core.Response;
import com.dreamsecurity.sso.lib.dss.s2.core.StatusCode;
import com.dreamsecurity.sso.lib.dss.s2.core.Subject;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmation;
import com.dreamsecurity.sso.lib.dss.s2.core.SubjectConfirmationData;
import com.dreamsecurity.sso.lib.dss.s2.metadata.AssertionConsumerService;
import com.dreamsecurity.sso.lib.dss.s2.metadata.Endpoint;
import com.dreamsecurity.sso.lib.dss.s2.metadata.RequestedAttribute;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor;
import com.dreamsecurity.sso.lib.dss.s2.metadata.SingleLogoutService;
import com.dreamsecurity.sso.lib.dsw.message.MessageContext;
import com.dreamsecurity.sso.lib.dsw.transport.http.HttpServletRequestAdapter;
import com.dreamsecurity.sso.lib.dsx.Configuration;
import com.dreamsecurity.sso.lib.dsx.io.MarshallingException;
import com.dreamsecurity.sso.lib.dsx.io.Unmarshaller;
import com.dreamsecurity.sso.lib.dsx.io.UnmarshallerFactory;
import com.dreamsecurity.sso.lib.dsx.schema.XSString;
import com.dreamsecurity.sso.lib.dsx.security.credential.Credential;
import com.dreamsecurity.sso.lib.dsx.signature.KeyInfo;
import com.dreamsecurity.sso.lib.dsx.signature.KeyValue;
import com.dreamsecurity.sso.lib.ism.client.SqlMapClient;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.lib.jtm.DateTime;
import com.dreamsecurity.sso.lib.jtm.DateTimeZone;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormat;
import com.dreamsecurity.sso.lib.jtm.format.DateTimeFormatter;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.api.UserApi;
import com.dreamsecurity.sso.server.api.UserApiFactory;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.crypto.SSOSecretKey;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.metadata.CredentialRepository;
import com.dreamsecurity.sso.server.metadata.MetadataRepository;
import com.dreamsecurity.sso.server.repository.connection.DBConnectMap;
import com.dreamsecurity.sso.server.session.AuthSession;
import com.dreamsecurity.sso.server.session.AuthnIssue;
import com.dreamsecurity.sso.server.session.OidcSessionManager;
import com.dreamsecurity.sso.server.session.RootAuthSession;
import com.dreamsecurity.sso.server.session.SessionManager;
import com.dreamsecurity.sso.server.token.LtpaToken;
import com.dreamsecurity.sso.server.token.SSOToken;
import com.dreamsecurity.sso.server.util.SAMLUtil;
import com.dreamsecurity.sso.server.util.Util;

public class IdentificationProvider extends CommonProvider
{
	private static Logger log = LoggerFactory.getLogger(IdentificationProvider.class);

	private static IdentificationProvider instance = null;

	public static final String ID_AUTHNREQUEST = "AuthnRequest";
	public static final String PARAM_SAMLREQUEST = "SAMLRequest";
	public static final String ID_AUTHSESSION = "AuthSession";
	public static final String PARAM_RELAYSTATE = "RelayState";

//	static {
//		try {
//			DefaultBootstrap.bootstrap();
//		}
//		catch (ConfigurationException e) {
//			e.printStackTrace();
//		}
//	}

	IdentificationProvider() throws SSOException
	{
		super();

		//setServerLicenseCheck(1);
		//setCreateLicenseMap(1);

//		status = SAMLCryptoApi.getInstance().ssoStartIntegrity();

//		AuditApi auditApi = new AuditApi();
//		setDupLoginType(auditApi.getDupLoginType());

		// if (status == -1)
		// ssoApi.sendMail("MSND0001", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), SSOConfig.getSiteName(), "");
	}

	public static IdentificationProvider getInstance() throws SSOException
	{
		if (instance == null) {
			synchronized (IdentificationProvider.class) {
				if (instance == null) {
					instance = new IdentificationProvider();
				}
			}
		}

		return instance;
	}

//	public int getCreateLicenseMap()
//	{
//		return createLicenseMap;
//	}
//
//	public void setCreateLicenseMap(int value)
//	{
//		this.createLicenseMap = value;
//	}
//
//	public String getDupLoginType()
//	{
//		return dupLoginType;
//	}
//
//	public void setDupLoginType(String value)
//	{
//		this.dupLoginType = value;
//	}

	// Install Test
	public Response generateResponse()
	{
		Response response = null;

		try {
			response = (Response) SAMLUtil.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
			SAMLUtil.checkAndMarshall(response);
		}
		catch (MarshallingException e) {
			e.printStackTrace();
		}

		return response;
	}

	public AuthnRequest receiveAuthnRequestTest(HttpServletRequest request)
	{
		MessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		SAMLMessageDecoder samlMessageDecoder = new HTTPPostDecoder();

		// decode & endpoint check
		try {
			samlMessageDecoder.decode(messageContext);
		}
		catch (Exception e) {
			log.error("### SAMLMessageDecoder.decode() Exception: {}", e.getMessage());
			return null;
		}

		AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundMessage();

		if (authnRequest == null) {
			log.error("### AuthnRequest Null");
			return null;
		}

		return authnRequest;
	}

	public int serviceCheck(HttpServletRequest request, StringBuffer xmlString)
	{
		String actionName = (String) (request.getParameter("actionName") != null ?
				request.getParameter("actionName"): request.getAttribute("actionName"));

		xmlString.append("<result>").append("<actionName>").append(actionName).append("</actionName>");

		// crypto library 동작 확인
		try {
			Credential idpCert = CredentialRepository.getCredential(SSOConfig.getInstance().getServerName(), MStatus.ENC_CERT);
			String result = SSOCryptoApi.getInstance().encryptPublicKey(idpCert, "dummy");
			log.debug("### serviceCheck::result = {}", result);
		}
		catch (Exception e) {
			log.error(e.toString());
			xmlString.append("<success>false</success>")
					.append("<code>-1</code>")
					.append("<key></key>")
					.append("<message><![CDATA[").append(e.getMessage()).append("]]></message>")
					.append("</result>");
			return -1;
		}

		// db 동작확인
		try {
			((SqlMapClient) DBConnectMap.getInstance().getConnection("default_db")).queryForObject("default_db_connCheck");

			xmlString.append("<success>true</success>")
					.append("<code>0</code>")
					.append("<key></key>")
					.append("<message>SUCCESS</message>")
					.append("</result>");
		}
		catch (SQLException e) {
			xmlString.append("<success>true</success>")
					.append("<code>").append(e.getErrorCode()).append("</code>")
					.append("<key></key>")
					.append("<message><![CDATA[").append(e.getMessage()).append("]]></message>")
					.append("</result>");
			return -1;
		}

		return 0;
	}

	public JSONObject receiveAuthnRequest(HttpServletRequest request)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### 인증 비활성화 상태");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "인증 비활성화 상태");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(true);

		String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");

		RootAuthSession rootAuthSession = null;

		int sessionLifespan = SSOConfig.getInstance().getInt("oidc.session.validtime", 24);
		DateTime rootAuthSessionExpDate = new DateTime().plusHours(sessionLifespan);

		if (Util.isEmpty(rootAuthSessionId)) {
			rootAuthSession = OidcSessionManager.getInstance().generateRootAuthSession(session);
		}
		else {
			rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);
		}

		// 동기화 서버에 요청
		if (rootAuthSession == null) {
			rootAuthSession = getRootAuthSessionByEvent(rootAuthSessionId);
		}

		// Cookie에는 존재하지만, rootAuthSession이 만료돼서 사라졌을 경우 재생성
		if (rootAuthSession == null) {
			rootAuthSession = OidcSessionManager.getInstance().generateRootAuthSession(session);
		}
		rootAuthSessionId = rootAuthSession.getSessionId();
		rootAuthSession.setExpDate(rootAuthSessionExpDate);

		// 로그인 시 이전 로그인 세션 제거
		String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");

		if (!Util.isEmpty(requestType) && requestType.equals("auth")) {
			String token = (String) session.getAttribute(SESSION_TOKEN);

			if (!Util.isEmpty(token)) {
				session.invalidate();
				session = request.getSession(true);
				session.setAttribute("DS_SESSION_ID", rootAuthSessionId);
			}
		}

		MessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		SAMLMessageDecoder samlMessageDecoder = new HTTPPostDecoder();

		// decode & endpoint check
		try {
			samlMessageDecoder.decode(messageContext);
		}
		catch (Exception e) {
			log.error("### SAMLMessageDecoder.decode() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_MESSAGE_DECODE));
			result.put("message", "SAMLMessageDecoder.decode() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundMessage();

		if (authnRequest == null) {
			log.error("### AuthnRequest Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "AuthnRequest Null");
			result.put("data", "");
			return result;
		}

		log.debug("### AuthnRequest:\n{}", Util.domToStr(authnRequest.getDOM().getOwnerDocument(), true));

		result = checkValidationAuthnRequest(authnRequest);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
					"AG", "1", "로그인 패킷 재사용");

			return result;
		}

		// C/S login check
		if (!Util.isEmpty(requestType) && requestType.equals("authc")) {
			try {
				String uid = authnRequest.getSubject().getNameID().getValue();
				String cdLoginTime = UserApiFactory.getUserApi().getCSLoginTime(uid);

				if (cdLoginTime.length() == 0) {
					log.error("### C/S Status Logout");

					result = null;
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_REQ_CS_LOGOUT));
					result.put("message", "C/S Status Logout");
					result.put("data", "");
					return result;
				}
			}
			catch (SSOException e) {
				log.error("### receiveAuthnRequest getUserApi SSOException : " + e.getMessage());

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(e.getErrorCode()));
				result.put("message", "receiveAuthnRequest getUserApi SSOException : " + e.getMessage());
				result.put("data", "");
				return result;
			}
		}

		result = null;
		result = EnvironInform.getInstance().checkLicense(authnRequest.getProviderName());

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		try {
			if (!SSOCryptoApi.getInstance().verifySignature(authnRequest)) {
				log.error("### AuthnRequest Verify Failure");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_VERIFY));
				result.put("message", "AuthnRequest Verify Failure");
				result.put("data", "");
				return result;
			}
		}
		catch (CryptoApiException e) {
			log.error("### SSOCryptoApi.getInstance() CryptoApiException: {}", e.getMessage());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.CRYPTO_INSTANCE));
			result.put("message", "SSOCryptoApi.getInstance() CryptoApiException: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		String strAuthnRequest = Util.domToStr(authnRequest.getDOM().getOwnerDocument(), false);
		session.setAttribute(ID_AUTHNREQUEST, strAuthnRequest);

		result = null;
		result = new JSONObject();
		result.put("code", String.valueOf(MStatus.SUCCESS));
		result.put("message", "SUCCESS");
		result.put("data", authnRequest);
		return result;
	}

	public JSONObject receiveGitlabAuthnRequest(HttpServletRequest request)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### 인증 비활성화 상태");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "인증 비활성화 상태");
			result.put("data", "");
			return result;
		}

		String spName = (String) request.getAttribute("spName");

		if (Util.isEmpty(spName)) {
			log.error("### receiveGitlabAuthnRequest: Empty SP Name");

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
			result.put("message", "Empty SP Name");
			result.put("data", "");
			return result;
		}

		String samlRequest = request.getParameter(PARAM_SAMLREQUEST);

		if (Util.isEmpty(samlRequest)) {
			request.setAttribute("authnID", SAMLUtil.createSamlId("_"));
			request.setAttribute("authnIssueTime", new DateTime(DateTimeZone.UTC));
		}
		else {
			MessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
			SAMLMessageDecoder samlMessageDecoder = new HTTPRedirectDeflateDecoder();

			// decode & endpoint(http://idp.dev.com:40001/sso/gitlabRequest.jsp) check 
			try {
				samlMessageDecoder.decode(messageContext);
			}
			catch (Exception e) {
				log.error("### receiveGitlabAuthnRequest: Exception: {}", e.getMessage());
	
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_MESSAGE_DECODE));
				result.put("message", "receiveGitlabAuthnRequest Exception: " + e.getMessage());
				result.put("data", "");
				return result;
			}

			AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundMessage();

			if (authnRequest == null) {
				log.error("### receiveGitlabAuthnRequest: AuthnRequest Null");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
				result.put("message", "AuthnRequest Null");
				result.put("data", "");
				return result;
			}

			log.debug("### Gitlab AuthnRequest:\n{}", Util.domToStr(authnRequest.getDOM().getOwnerDocument(), true));

			result = checkValidationAuthnRequest(authnRequest);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				return result;
			}

			String authnSP = authnRequest.getIssuer().getValue();

			if (!authnSP.equals(spName)) {
				log.error("### receiveGitlabAuthnRequest: Invalid Issuer");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
				result.put("message", "Invalid Issuer");
				result.put("data", "");
				return result;
			}

			try {
				SPSSODescriptor spDes = MetadataRepository.getInstance().getSPDescriptor(spName);
				String spEndpoint = spDes.getDefaultAssertionConsumerService().getLocation();

				if (!spEndpoint.equals(authnRequest.getAssertionConsumerServiceURL())) {
					log.error("### receiveGitlabAuthnRequest: Invalid SP Endpoint");

					result = null;
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
					result.put("message", "Invalid SP Endpoint");
					result.put("data", "");
					return result;
				}
			}
			catch (SSOException e) {
				log.error("### receiveGitlabAuthnRequest: SSOException: {}", e.getMessage());
	
				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
				result.put("message", "receiveGitlabAuthnRequest SSOException: " + e.getMessage());
				result.put("data", "");
				return result;
			}

			request.setAttribute("authnID", authnRequest.getID());
			request.setAttribute("authnIssueTime", authnRequest.getIssueInstant());
		}

		// License (only domain)
		result = null;
		result = EnvironInform.getInstance().checkLicense(spName);

		if (Integer.parseInt((String) result.get("code")) == MStatus.SUCCESS) {
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String checkVal = licMap.get(spName);

			if (checkVal.length() > 1) {  // IP
				log.error("### receiveGitlabAuthnRequest: Domain License Error");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
				result.put("message", "SP Server [" + spName + "] Domain License Error");
				result.put("data", "");
			}
		}

		return result;
	}

	public JSONObject receiveStdAuthnRequest(HttpServletRequest request)
	{
		JSONObject result = null;

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### 인증 비활성화 상태");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "인증 비활성화 상태");
			result.put("data", "");
			return result;
		}

		String spName = (String) request.getAttribute("spName");

		if (Util.isEmpty(spName)) {
			log.error("### receiveStdAuthnRequest: Empty SP Name");

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
			result.put("message", "Empty SP Name");
			result.put("data", "");
			return result;
		}

		String samlRequest = request.getParameter(PARAM_SAMLREQUEST);

		if (Util.isEmpty(samlRequest)) {
			request.setAttribute("authnID", SAMLUtil.createSamlId("_"));
			request.setAttribute("authnIssueTime", new DateTime(DateTimeZone.UTC));
		}
		else {
			MessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
			SAMLMessageDecoder samlMessageDecoder = new HTTPRedirectDeflateDecoder();

			// decode & endpoint(http://idp.dev.com:40001/sso/gitlabRequest.jsp) check 
			try {
				samlMessageDecoder.decode(messageContext);
			}
			catch (Exception e) {
				log.error("### receiveStdAuthnRequest: Exception: {}", e.getMessage());
	
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_MESSAGE_DECODE));
				result.put("message", "receiveStdAuthnRequest Exception: " + e.getMessage());
				result.put("data", "");
				return result;
			}

			AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundMessage();

			if (authnRequest == null) {
				log.error("### receiveStdAuthnRequest: AuthnRequest Null");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
				result.put("message", "AuthnRequest Null");
				result.put("data", "");
				return result;
			}

			log.debug("### receiveStdAuthnRequest:\n{}", Util.domToStr(authnRequest.getDOM().getOwnerDocument(), true));

			result = checkValidationAuthnRequest(authnRequest);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				return result;
			}

			String authnSP = authnRequest.getIssuer().getValue();

			if (!authnSP.equals(spName)) {
				log.error("### receiveStdAuthnRequest: Invalid Issuer");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
				result.put("message", "Invalid Issuer");
				result.put("data", "");
				return result;
			}

			try {
				SPSSODescriptor spDes = MetadataRepository.getInstance().getSPDescriptor(spName);
				String spEndpoint = spDes.getDefaultAssertionConsumerService().getLocation();

				if (!spEndpoint.equals(authnRequest.getAssertionConsumerServiceURL())) {
					log.error("### receiveStdAuthnRequest: Invalid SP Endpoint");

					result = null;
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
					result.put("message", "Invalid SP Endpoint");
					result.put("data", "");
					return result;
				}
			}
			catch (SSOException e) {
				log.error("### receiveStdAuthnRequest: SSOException: {}", e.getMessage());
	
				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
				result.put("message", "receiveStdAuthnRequest SSOException: " + e.getMessage());
				result.put("data", "");
				return result;
			}

			request.setAttribute("authnID", authnRequest.getID());
			request.setAttribute("authnIssueTime", authnRequest.getIssueInstant());
		}

		// License (only domain)
		result = null;
		result = EnvironInform.getInstance().checkLicense(spName);

		if (Integer.parseInt((String) result.get("code")) == MStatus.SUCCESS) {
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String checkVal = licMap.get(spName);

			if (checkVal.length() > 1) {  // IP
				log.error("### receiveStdAuthnRequest: Domain License Error");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
				result.put("message", "SP Server [" + spName + "] Domain License Error");
				result.put("data", "");
			}
		}

		return result;
	}

	private JSONObject checkValidationAuthnRequest(AuthnRequest authnRequest)
	{
		JSONObject result = new JSONObject();

		boolean dupAuthnReq = SessionManager.getInstance().addAuthnRequest(authnRequest);

		if (dupAuthnReq) {
			log.error("### AuthnRequest Duplicate");

			result.put("code", String.valueOf(MStatus.AUTH_REQ_DUPLICATE));
			result.put("message", "AuthnRequest Duplicate");

			try {
				result.put("data", authnRequest.getSubject().getNameID().getValue());
			}
			catch (Exception e) {
				result.put("data", authnRequest.getIssuer().getValue());
			}

			return result;
		}

		DateTime dateTime = new DateTime(DateTimeZone.UTC).minusMinutes(SSOConfig.getInstance().getRequestTimeout());

		if (dateTime.compareTo(authnRequest.getIssueInstant()) > 0) {
			log.error("### AuthnRequest Timeout");

			result.put("code", String.valueOf(MStatus.AUTH_REQ_TIMEOUT));
			result.put("message", "AuthnRequest Timeout");

			try {
				result.put("data", authnRequest.getSubject().getNameID().getValue());
			}
			catch (Exception e) {
				result.put("data", authnRequest.getIssuer().getValue());
			}

			return result;
		}

		result.put("code", String.valueOf(MStatus.SUCCESS));
		result.put("message", "SUCCESS");
		result.put("data", "");
		return result;
	}

	public JSONObject receiveRequestS(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### 인증 비활성화 상태");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			HttpSession session = request.getSession(true);

			String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");
			String requestData = request.getParameter("RequestData") == null ? "" : request.getParameter("RequestData");

			if (Util.isEmpty(requestType))
				requestType = request.getAttribute("RequestType") == null ? "" : (String) request.getAttribute("RequestType");

			if (Util.isEmpty(requestData))
				requestData = request.getAttribute("RequestData") == null ? "" : (String) request.getAttribute("RequestData");

			// 로그인 시 이전 로그인 세션 제거
			if (!Util.isEmpty(requestType) && requestType.equals("auth")) {
				String token = (String) session.getAttribute(SESSION_TOKEN);

				if (!Util.isEmpty(token)) {
					session.invalidate();
					session = request.getSession(true);
				}
			}

			if (Util.isEmpty(requestData)) {
				log.error("### RequestData Empty");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DATA_EMPTY));
				result.put("message", "RequestData Empty");
				result.put("data", "");
				return result;
			}

			// Decrypt Data
			JSONObject jsonData = SSOCryptoApi.getInstance().decryptJsonObject(requestData);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AW", "0", (String) jsonData.get("xfr") + "," + (String) jsonData.get("id") + "," + Util.getClientIP(request)
					+ ",로그인 요청 전송정보 복호화 후 파기,0 으로 덮어쓰기");

			//log.debug("### Request Data:\n" + jsonData.toString());

			// Check License
			result = EnvironInform.getInstance().checkLicense((String) jsonData.get("xfr"));

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			request.setAttribute(ID_AUTHNREQUEST, jsonData);

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		catch (CryptoApiException e) {
			if (e.getCode() == MStatus.ERR_DATA_VERIFY) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), "None",
						"AG", "1", "로그인 패킷 재사용");
			}

			log.error("### receiveRequestS CryptoApiException: " + e.getMessage());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.CRYPTO_DECRYPT));
			result.put("message", "receiveRequestS CryptoApiException: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject receiveDominoRequestS(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### 인증 비활성화 상태");

				result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			HttpSession session = request.getSession(true);

			String proc = request.getParameter("reqType") == null ? "" : request.getParameter("reqType");
			String uid = request.getParameter("loginId") == null ? "" : request.getParameter("loginId");
			String upw = request.getParameter("loginPw") == null ? "" : request.getParameter("loginPw");
			String relay = request.getParameter("returnUrl") == null ? "" : request.getParameter("returnUrl");

			if (Util.isEmpty(proc) || (!proc.equals("auth") && !proc.equals("connect"))) {
				log.error("### Invalid Request Data(1)");

				result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DATA_INVALID));
				result.put("message", "Invalid Request Data(1)");
				result.put("data", "");
				return result;
			}

			if (proc.equals("auth") && (Util.isEmpty(uid) || Util.isEmpty(upw))) {
				log.error("### Invalid Request Data(2)");

				result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DATA_INVALID));
				result.put("message", "Invalid Request Data(2)");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(relay)) {
				log.error("### Invalid Request Data(3)");

				result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DATA_INVALID));
				result.put("message", "Invalid Request Data(3)");
				result.put("data", "");
				return result;
			}

			String tokenStr = (String) session.getAttribute(SESSION_TOKEN);

			// 로그인 시, ID가 다른 로그인 세션이 존재하면 제거
			if (proc.equals("auth")) {
				if (!Util.isEmpty(tokenStr)) {
					SSOToken token = new SSOToken(tokenStr);

					if (!uid.equals(token.getId())) {
						token.finalize();
						Util.zeroize(tokenStr);

						session.invalidate();
						session = request.getSession(true);
					}
				}
			}
			else if (proc.equals("connect")) {
				if (Util.isEmpty(tokenStr)) {
					log.error("### Not Login Status");

					result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
					result.put("message", "Not Login Status");
					result.put("data", "");
					return result;
				}
			}

			boolean bAuthn = proc.equals("auth") ? true : false;

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", bAuthn);
		}
		catch (Throwable e) {
			log.error("### receiveDominoRequestS Exception: " + e.getMessage());

			result.put("code", String.valueOf(MStatus.AUTH_EXCEPTION));
			result.put("message", "receiveDominoRequestS Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject receiveSiluetRequestS(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### 인증 비활성화 상태");

				result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			HttpSession session = request.getSession(true);

			String relay = request.getParameter("returnUrl") == null ? "" : request.getParameter("returnUrl");

			if (Util.isEmpty(relay)) {
				log.error("### Invalid Request Data");

				result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DATA_INVALID));
				result.put("message", "Invalid Request Data");
				result.put("data", "");
				return result;
			}

			String tokenStr = (String) session.getAttribute(SESSION_TOKEN);

			if (Util.isEmpty(tokenStr)) {
				log.error("### Not Login Status");

				result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
				result.put("message", "Not Login Status");
				result.put("data", "");
				return result;
			}

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### receiveSiluetteRequestS Exception: " + e.getMessage());

			result.put("code", String.valueOf(MStatus.AUTH_EXCEPTION));
			result.put("message", "receiveSiluetRequestS Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public boolean checkAuthenticationS(HttpServletRequest request)
	{
		// return: true = login, false = connect
		HttpSession session = request.getSession(false);

		String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");

		if (Util.isEmpty(requestType))
			requestType = request.getAttribute("RequestType") == null ? "" : (String) request.getAttribute("RequestType");

		if (Util.isEmpty(requestType)) {
			return true;
		}
		else if (requestType.equals("auth")) {
			return true;
		}
		else if (requestType.equals("connect") || requestType.equals("authc")) {
			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String tokenDEK = (String) session.getAttribute(SESSION_TOKEN_EK);

			if (Util.isEmpty(encToken) || Util.isEmpty(tokenDEK)) {
				return true;
			}

			SSOToken token = null;

			try {
				token = SSOCryptoApi.getInstance().decryptToken(encToken, tokenDEK);
			}
			catch (Exception e) {
				token = null;
			}

			if (token == null) {
				return true;
			}

			// C/S Web 연계 처리
			if ( requestType.equals("authc")) {
				JSONObject jsonData = (JSONObject) request.getAttribute(ID_AUTHNREQUEST);

				if (jsonData == null) {
					return true;
				}

				String id = (String) jsonData.get("id");

				if (!id.equals(token.getId())) {
					session.invalidate();
					session = request.getSession(true);

					return true;
				}
			}

			// 연계 시 AuthSession 검증
			AuthSession authSession = (AuthSession) session.getAttribute(ID_AUTHSESSION);

			if (SessionManager.getInstance().compareSession(token.getId(), authSession)) {
					try { token.finalize(); } catch (Throwable e) {}

					log.info("### AuthSession Compare Result: True (connect)");
					return false;
			}
		}
		else if (requestType.equals("connectExM")) {  // Mobile App to Web
			return false;
		}
		else {
		}

		return true;
	}

	public JSONObject checkSessionAuthenInfo(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();

		HttpSession session = request.getSession(false);

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String tokenDEK = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(tokenDEK)) {
			log.error("### Not Login Status");

			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login Status");
			result.put("data", "");
			return result;
		}

		SSOToken token = null;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, tokenDEK);
		}
		catch (Exception e) {
			token = null;
		}

		if (token == null) {
			log.error("### Not Login Status");

			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login Status");
			result.put("data", "");
			return result;
		}

		// 연계 시 AuthSession 검증
		AuthSession authSession = (AuthSession) session.getAttribute(ID_AUTHSESSION);

		if (SessionManager.getInstance().compareSession(token.getId(), authSession)) {
			try { token.finalize(); } catch (Throwable e) {}

			log.info("### AuthSession Compare Result: True (connect)");

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		else {
			log.error("### Not Login Status");

			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login Status");
			result.put("data", "");
		}

		return result;
	}

	public JSONObject checkSessionAuthenInfoS(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();

		SSOConfig config = SSOConfig.getInstance();

		if (config.getAuthStatus() != 0) {
			log.error("### 인증 비활성화 상태");

			result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
			result.put("message", "인증 비활성화 상태");
			result.put("data", "");
			return result;
		}

		String spName = (String) request.getAttribute("spName");

		if (Util.isEmpty(spName)) {
			log.error("### checkSessionAuthenInfoS: Empty SP Name");

			result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
			result.put("message", "Empty SP Name");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String tokenDEK = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(tokenDEK)) {
			log.error("### checkSessionAuthenInfoS: Not Login Status");

			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login Status");
			result.put("data", "");
			return result;
		}

		SSOToken token = null;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, tokenDEK);
		}
		catch (Exception e) {
			token = null;
		}

		if (token == null) {
			log.error("### checkSessionAuthenInfoS: Not Login Status(1)");

			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login Status");
			result.put("data", "");
			return result;
		}

		// AuthSession
		AuthSession authSession = (AuthSession) session.getAttribute(ID_AUTHSESSION);

		if (SessionManager.getInstance().compareSession(token.getId(), authSession)) {
			try { token.finalize(); } catch (Throwable e) {}

			log.info("### checkSessionAuthenInfoS: AuthSession Compare Result: True");
		}
		else {
			log.error("### checkSessionAuthenInfoS: Not Login Status(2)");

			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login Status");
			result.put("data", "");
			return result;
		}

		// License (only domain)
		result = EnvironInform.getInstance().checkLicense(spName);

		if (Integer.parseInt((String) result.get("code")) == MStatus.SUCCESS) {
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String checkVal = licMap.get(spName);

			if (checkVal.length() > 1) {  // IP
				log.error("### checkSessionAuthenInfoS: Domain License Error");

				result = null;
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.LICENSE_VERIFY));
				result.put("message", "SP Server [" + spName + "] Domain License Error");
				result.put("data", "");
			}
		}

		return result;
	}

	public String getResponseUrl(String providerName, String relayState)
	{
		try {
			SPSSODescriptor spDesc = MetadataRepository.getInstance().getSPDescriptor(providerName);
			Endpoint endpoint = getEndpoint(relayState, spDesc);
			return endpoint.getLocation();
		}
		catch (Exception e) {
			log.error("### " + e.toString());
			return "";
		}
	}

	private Endpoint getEndpoint(String relayState, SPSSODescriptor spDesc)
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
			log.info("### RelayState is not URL : " + relay);
			return spDesc.getDefaultAssertionConsumerService();
		}

		String relayHost = relayUrl.getHost();

		if (Util.isEmpty(relayHost)) {
			return spDesc.getDefaultAssertionConsumerService();
		}

		// RelayState URL과 ServiceDiscriptor URL을 비교하여 일치하는 service를 return
		List<AssertionConsumerService> serviceList = spDesc.getAssertionConsumerServices();
		log.debug("### AssertionConsumerService size : " + serviceList.size());

		for (int i = 0; i < serviceList.size(); i++) {
			AssertionConsumerService service = serviceList.get(i);

			try {
				log.debug("### AssertionConsumerService location : " + service.getLocation());
				if (relayHost.equals(new URL(service.getLocation()).getHost())) {
					return service;
				}
			}
			catch (Exception e) {
				log.info("### AssertionConsumerService is not URL : " + service.getLocation());
			}
		}

		return spDesc.getDefaultAssertionConsumerService();
	}

	public boolean checkAuthentication(HttpServletRequest request)
	{
		// return: true = login, false = connect

		HttpSession session = request.getSession(false);
		AuthnRequest authnRequest = getAuthnRequest(session);

		if (authnRequest == null) {
			return true;
		}

		if (authnRequest.isPassive().booleanValue()) {
			return false;
		}

		if (authnRequest.isForceAuthn().booleanValue()) {
			return true;
		}

		Subject subject = authnRequest.getSubject();
		if (subject == null) {
			authnRequest = null;
			return true;
		}

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String tokenDEK = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(tokenDEK)) {
			authnRequest = null;
			return true;
		}

		SSOToken token = null;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, tokenDEK);
		}
		catch (Exception e) {
			token = null;
		}

		if (token == null) {
			authnRequest = null;
			return true;
		}

		// C/S Web 연계 처리
		String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");

		if (!Util.isEmpty(requestType) && requestType.equals("authc")) {
			String nameid = authnRequest.getSubject().getNameID().getValue();

			if (!nameid.equals(token.getId())) {
				session.invalidate();
				session = request.getSession(true);

				authnRequest = null;
				return true;
			}
		}

		// 연계 시 AuthSession 검증
		AuthSession authSession = (AuthSession) session.getAttribute(ID_AUTHSESSION);

		if (SessionManager.getInstance().compareSession(token.getId(), authSession,
					authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs())) {
			authnRequest = null;
			try { token.finalize(); } catch (Throwable e) {}

			log.info("### AuthSession Compare Result: True (connect)");
			return false;
		}

		authnRequest = null;
		try { token.finalize(); } catch (Throwable e) {}

		log.info("### AuthSession Compare Result: FALSE (login)");
		return true;
	}

	public boolean checkIDPLogin(HttpServletRequest request)
	{
		if (!SSOConfig.getInstance().getServerLogin()) {
			return false;
		}

		HttpSession session = request.getSession(false);
		AuthnRequest authnRequest = getAuthnRequest(session);

		if (authnRequest == null) {
			return false;
		}

		Subject subject = authnRequest.getSubject();
		if (subject == null) {
			authnRequest = null;
			return false;
		}

		String nameid = authnRequest.getSubject().getNameID().getValue();

		if (Util.isEmpty(nameid)) {
			authnRequest = null;
			return false;
		}

		if (!nameid.equals(SUBJECT_EMPTY_ID)) {
			authnRequest = null;
			return false;
		}

		log.info("### IDP Login: true");

		authnRequest = null;
		return true;
	}

	public boolean checkIDPLoginS(HttpServletRequest request)
	{
		if (!SSOConfig.getInstance().getServerLogin()) {
			return false;
		}

		String requestType = Util.getRequestParam(request, "RequestType");

		if (!requestType.equals("connect")) {
			return false;
		}

		JSONObject jsonData = (JSONObject) request.getAttribute(ID_AUTHNREQUEST);

		if (jsonData == null) {
			return false;
		}

		String id = (String) jsonData.get("id");

		if (Util.isEmpty(id)) {
			return false;
		}

		if (!id.equals(SUBJECT_EMPTY_ID)) {
			return false;
		}

		HttpSession session = request.getSession(true);
		session.setAttribute(ID_AUTHNREQUEST, jsonData);

		log.info("### IDP Login 2: true");

		return true;
	}

	public AuthnRequest getAuthnRequest(HttpSession session)
	{
		String strAuthnRequest = (String) session.getAttribute(ID_AUTHNREQUEST);
		AuthnRequest authnRequest = null;

		if (!Util.isEmpty(strAuthnRequest)) {
			Document domDoc = Util.createDomDoc(strAuthnRequest);
			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(domDoc.getDocumentElement());

			try {
				authnRequest = (AuthnRequest) unmarshaller.unmarshall(domDoc.getDocumentElement());
			}
			catch (Exception e) {
				authnRequest = null;
				log.error("### getAuthnRequest() Exception: {}", e.getMessage());
			}
		}

		return authnRequest;
	}

	public JSONObject authnIDPLogin(HttpServletRequest request, String id, String pw)
	{
		JSONObject result = null;

		HttpSession session = request.getSession(false);

		if (Util.isEmpty(id) || Util.isEmpty(pw)) {
			session.removeAttribute("LACHLG");

			log.error("### authnIDPLogin: Parameter Empty");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_PARAMETER));
			result.put("message", "Parameter Empty");
			result.put("data", "");
			return result;
		}

		String ch = Util.getAttribute(session, "LACHLG");
		session.removeAttribute("LACHLG");

		if (Util.isEmpty(ch)) {
			log.error("### authnIDPLogin: CSRFToken Invalid");

			result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DATA_INVALID));
			result.put("message", "Login CSRFToken Invalid");
			result.put("data", "");
			return result;
		}

		try {
			id = SSOCryptoApi.getInstance().decryptJS(ch, id);
			pw = SSOCryptoApi.getInstance().decryptJS(ch, pw);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
			log.error("### authnIDPLogin: Decrypt Failure");

			result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DECRYPT_FAIL));
			result.put("message", "Login Data Decrypt Failure");
			result.put("data", "");
			return result;
		}

		AuthnRequest authnRequest = getAuthnRequest(session);

		if (authnRequest == null) {
			log.error("### authnIDPLogin: AuthnRequest Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "AuthnRequest Null");
			result.put("data", "");
			return result;
		}

		result = EnvironInform.getInstance().checkLicense(authnRequest.getProviderName());

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		Subject subject = authnRequest.getSubject();

		if (subject == null) {
			authnRequest = null;
			log.error("### authnIDPLogin: AuthnRequest Subject Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_SUBJECT_NULL));
			result.put("message", "AuthnRequest Subject Null");
			result.put("data", "");
			return result;
		}

		NameID nameID = subject.getNameID();

		if (!NameID.ENTITY.equals(nameID.getFormat())) {
			authnRequest = null;
			log.error("### authnIDPLogin: AuthnRequest Subject:NameID Format Invalid");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "AuthnRequest Subject:NameID Format Invalid");
			result.put("data", "");
			return result;
		}

		String nameid = nameID.getValue();

		String sid = null;
		String spName = authnRequest.getIssuer().getValue();

		request.setAttribute("spname", spName);
		request.setAttribute("logintype", "ID_PW");

		byte[] decKey = null;
		byte[] byteData = null;
		String strData = null;
		SSOSecretKey secKey = null;

		try {
			SubjectConfirmationData subjectData = ((SubjectConfirmation) subject.getSubjectConfirmations().get(0)).getSubjectConfirmationData();
			SAMLUtil.checkAndMarshall(subjectData);
			KeyInfo keyInfo = (KeyInfo) subjectData.getUnknownXMLObjects().get(0);

			KeyValue keyValue_0 = (KeyValue) keyInfo.getKeyValues().get(0);
			XSString xsString_0 = (XSString) keyValue_0.getUnknownXMLObject();
			String encData = xsString_0.getValue();

			KeyValue keyValue_1 = (KeyValue) keyInfo.getKeyValues().get(1);
			XSString xsString_1 = (XSString) keyValue_1.getUnknownXMLObject();
			String encKey = xsString_1.getValue();

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			decKey = cryptoApi.decryptPrivateKey(encKey);
			secKey = new SSOSecretKey("SEED", decKey);
			byteData = cryptoApi.decrypt(secKey, encData);
			strData = new String(byteData, "UTF-8");

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(strData);

			String uid = (String) jsonData.get("id");
			String appl = (String) jsonData.get("appl");
			sid = (String) jsonData.get("sid");
			String spip = (String) jsonData.get("spip");
			String xid = (String) jsonData.get("xid");
			String xtm = (String) jsonData.get("xtm");

			DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZoneUTC();
			DateTime issueTime = format.parseDateTime(xtm);

			// 암호키 파기
			Util.zeroize(decKey);
			Util.zeroize(byteData);
			Util.zeroize(strData);
			secKey.finalize();

			if (!xid.equals(authnRequest.getID())) {
				authnRequest = null;
				log.error("### authnIDPLogin: AuthnRequest ID Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ID_INVALID));
				result.put("message", "AuthnRequest ID Invalid");
				result.put("data", "");
				return result;
			}

			if (!issueTime.equals(authnRequest.getIssueInstant())) {
				authnRequest = null;
				log.error("### authnIDPLogin: AuthnRequest Issue Time Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ISSUE_TIME_INVALID));
				result.put("message", "AuthnRequest Issue Time Invalid");
				result.put("data", "");
				return result;
			}

			if (!uid.equals(nameid)) {
				authnRequest = null;
				log.error("### authnIDPLogin: AuthnRequest Subject:NameID Value Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
				result.put("message", "AuthnRequest Subject:NameID Value Invalid");
				result.put("data", "");
				return result;
			}

			request.setAttribute("id", id);
			request.setAttribute("pw", pw);
			request.setAttribute("applcode", appl);

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						authnRequest = null;
						log.error("### authnIDPLogin: AuthnRequest Subject:IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "AuthnRequest Subject:IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					authnRequest = null;
					log.error("### authnIDPLogin: AuthnRequest Subject:IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "AuthnRequest Subject:IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// 로그인
			result = null;
			result = UserApiFactory.getUserApi().login(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			result.put("data", authnRequest);
			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);
		}
		catch (Exception e) {
			authnRequest = null;
			log.error("### authnIDPLogin: Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnIDPLogin: Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject authnLogin(HttpServletRequest request)
	{
		JSONObject result = null;

		String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");

		if (requestType.equals("connect")) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login State");
			result.put("data", "");
			return result;
		}

		HttpSession session = request.getSession(false);
		AuthnRequest authnRequest = getAuthnRequest(session);

		if (authnRequest == null) {
			log.error("### AuthnRequest Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "AuthnRequest Null");
			result.put("data", "");
			return result;
		}

		String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");
		RootAuthSession rootAuthSession = null;
		rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);

		result = EnvironInform.getInstance().checkLicense(authnRequest.getProviderName());

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		Subject subject = authnRequest.getSubject();

		if (subject == null) {
			authnRequest = null;
			log.error("### AuthnRequest Subject Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_SUBJECT_NULL));
			result.put("message", "AuthnRequest Subject Null");
			result.put("data", "");
			return result;
		}

		NameID nameID = subject.getNameID();

		if (!NameID.ENTITY.equals(nameID.getFormat())) {
			authnRequest = null;
			log.error("### AuthnRequest Subject:NameID Format Invalid");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "AuthnRequest Subject:NameID Format Invalid");
			result.put("data", "");
			return result;
		}

		String nameid = nameID.getValue();

		if (nameid.equals(CommonProvider.SUBJECT_LOGIN_CERT)) {
			return authnLoginCert(request);
		}

		String sid = null;
		String spName = authnRequest.getIssuer().getValue();

		request.setAttribute("spname", spName);
		request.setAttribute("logintype", "ID_PW");

		byte[] decKey = null;
		byte[] byteData = null;
		String strData = null;
		SSOSecretKey secKey = null;

		try {
			SubjectConfirmationData subjectData = ((SubjectConfirmation) subject.getSubjectConfirmations().get(0)).getSubjectConfirmationData();
			SAMLUtil.checkAndMarshall(subjectData);
			KeyInfo keyInfo = (KeyInfo) subjectData.getUnknownXMLObjects().get(0);

			KeyValue keyValue_0 = (KeyValue) keyInfo.getKeyValues().get(0);
			XSString xsString_0 = (XSString) keyValue_0.getUnknownXMLObject();
			String encData = xsString_0.getValue();

			KeyValue keyValue_1 = (KeyValue) keyInfo.getKeyValues().get(1);
			XSString xsString_1 = (XSString) keyValue_1.getUnknownXMLObject();
			String encKey = xsString_1.getValue();

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			decKey = cryptoApi.decryptPrivateKey(encKey);
			secKey = new SSOSecretKey("SEED", decKey);
			byteData = cryptoApi.decrypt(secKey, encData);
			strData = new String(byteData, "UTF-8");

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(strData);

			String id = (String) jsonData.get("id");
			String pw = (String) jsonData.get("pw");
			String appl = (String) jsonData.get("appl");
			sid = (String) jsonData.get("sid");
			String spip = (String) jsonData.get("spip");
			String xid = (String) jsonData.get("xid");
			String xtm = (String) jsonData.get("xtm");

			DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZoneUTC();
			DateTime issueTime = format.parseDateTime(xtm);

			// 암호키 파기
			Util.zeroize(decKey);
			Util.zeroize(byteData);
			Util.zeroize(strData);
			secKey.finalize();

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AW", "0", spName + "," + id + "," + Util.getClientIP(request) + ",로그인 요청 전송정보 복호화 후 파기,0 으로 덮어쓰기");

			if (!xid.equals(authnRequest.getID())) {
				authnRequest = null;
				log.error("### AuthnRequest ID Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ID_INVALID));
				result.put("message", "AuthnRequest ID Invalid");
				result.put("data", "");
				return result;
			}

			if (!issueTime.equals(authnRequest.getIssueInstant())) {
				authnRequest = null;
				log.error("### AuthnRequest Issue Time Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ISSUE_TIME_INVALID));
				result.put("message", "AuthnRequest Issue Time Invalid");
				result.put("data", "");
				return result;
			}

			if (!id.equals(nameid)) {
				authnRequest = null;
				log.error("### AuthnRequest Subject:NameID Value Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
				result.put("message", "AuthnRequest Subject:NameID Value Invalid");
				result.put("data", "");
				return result;
			}

			request.setAttribute("id", id);
			request.setAttribute("pw", pw);
			request.setAttribute("applcode", appl);

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						authnRequest = null;
						log.error("### AuthnRequest Subject:IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "AuthnRequest Subject:IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					authnRequest = null;
					log.error("### AuthnRequest Subject:IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "AuthnRequest Subject:IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// 로그인
			result = null;
			result = UserApiFactory.getUserApi().login(request, rootAuthSession);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);

			int sessionLifespan = SSOConfig.getInstance().getInt("oidc.session.validtime", 24);
			DateTime rootAuthSessionExpDate = new DateTime().plusHours(sessionLifespan);
			rootAuthSession.setExpDate(rootAuthSessionExpDate);
			
			SyncMonitor.startMonitor();
			SyncMonitor.registOidcAuthEvent(rootAuthSession);

//			log.debug("### Check DupLogin : " + MemConfig.getInstance().getDupLoginType());
//
//			// 중복로그인 체크 (0:허용, 1:선입자우선, 2:후입자우선)
//			if (!MemConfig.getInstance().getDupLoginType().equals("0")) {
//				// 기존 동일 사용자로 로그인한 정보가 있다면 삭제(중복로그인 방지)
//				logoutRequestToOther(request);
//			}
		}
		catch (Exception e) {
			authnRequest = null;
			log.error("### authnLogin() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnLogin() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject authnLoginCert(HttpServletRequest request)
	{
		JSONObject result = null;

		HttpSession session = request.getSession(false);
		AuthnRequest authnRequest = getAuthnRequest(session);

		if (authnRequest == null) {
			log.error("### AuthnRequest Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "AuthnRequest Null");
			result.put("data", "");
			return result;
		}

		result = EnvironInform.getInstance().checkLicense(authnRequest.getProviderName());

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		Subject subject = authnRequest.getSubject();

		if (subject == null) {
			authnRequest = null;
			log.error("### AuthnRequest Subject Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_SUBJECT_NULL));
			result.put("message", "AuthnRequest Subject Null");
			result.put("data", "");
			return result;
		}

		NameID nameID = subject.getNameID();

		if (!NameID.ENTITY.equals(nameID.getFormat())) {
			authnRequest = null;
			log.error("### AuthnRequest Subject:NameID Format Invalid");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "AuthnRequest Subject:NameID Format Invalid");
			result.put("data", "");
			return result;
		}

		String nameid = nameID.getValue();

		if (!nameid.equals(CommonProvider.SUBJECT_LOGIN_CERT)) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "AuthnRequest Subject:NameID Value Invalid");
			result.put("data", "");
			return result;
		}

		String sid = null;
		String spName = authnRequest.getIssuer().getValue();

		request.setAttribute("spname", spName);
		request.setAttribute("logintype", "CERT");

		byte[] decKey = null;
		byte[] byteData = null;
		String strData = null;
		SSOSecretKey secKey = null;

		try {
			SubjectConfirmationData subjectData = ((SubjectConfirmation) subject.getSubjectConfirmations().get(0)).getSubjectConfirmationData();
			SAMLUtil.checkAndMarshall(subjectData);
			KeyInfo keyInfo = (KeyInfo) subjectData.getUnknownXMLObjects().get(0);

			KeyValue keyValue_0 = (KeyValue) keyInfo.getKeyValues().get(0);
			XSString xsString_0 = (XSString) keyValue_0.getUnknownXMLObject();
			String encData = xsString_0.getValue();

			KeyValue keyValue_1 = (KeyValue) keyInfo.getKeyValues().get(1);
			XSString xsString_1 = (XSString) keyValue_1.getUnknownXMLObject();
			String encKey = xsString_1.getValue();

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			decKey = cryptoApi.decryptPrivateKey(encKey);
			secKey = new SSOSecretKey("SEED", decKey);
			byteData = cryptoApi.decrypt(secKey, encData);
			strData = new String(byteData, "UTF-8");

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(strData);

			String signedData = (String) jsonData.get("signed");
			String appl = (String) jsonData.get("appl");
			sid = (String) jsonData.get("sid");
			String spip = (String) jsonData.get("spip");
			String xid = (String) jsonData.get("xid");
			String xtm = (String) jsonData.get("xtm");

			DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZoneUTC();
			DateTime issueTime = format.parseDateTime(xtm);

			// 암호키 파기
			Util.zeroize(decKey);
			Util.zeroize(byteData);
			Util.zeroize(strData);
			secKey.finalize();

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AW", "0", spName + ",인증서," + Util.getClientIP(request) + ",로그인 요청 전송정보 복호화 후 파기,0 으로 덮어쓰기");

			if (!xid.equals(authnRequest.getID())) {
				authnRequest = null;
				log.error("### AuthnRequest ID Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ID_INVALID));
				result.put("message", "AuthnRequest ID Invalid");
				result.put("data", "");
				return result;
			}

			if (!issueTime.equals(authnRequest.getIssueInstant())) {
				authnRequest = null;
				log.error("### AuthnRequest Issue Time Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AG", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ISSUE_TIME_INVALID));
				result.put("message", "AuthnRequest Issue Time Invalid");
				result.put("data", "");
				return result;
			}

			request.setAttribute("signed", signedData);
			request.setAttribute("applcode", appl);

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						authnRequest = null;
						log.error("### AuthnRequest Subject:IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "AuthnRequest Subject:IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					authnRequest = null;
					log.error("### AuthnRequest Subject:IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "AuthnRequest Subject:IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// 로그인
			result = null;
			result = UserApiFactory.getUserApi().loginCert(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);

//			log.debug("### Check DupLogin : " + MemConfig.getInstance().getDupLoginType());
//
//			// 중복로그인 체크 (0:허용, 1:선입자우선, 2:후입자우선)
//			if (!MemConfig.getInstance().getDupLoginType().equals("0")) {
//				// 기존 동일 사용자로 로그인한 정보가 있다면 삭제(중복로그인 방지)
//				logoutRequestToOther(request);
//			}
		}
		catch (Exception e) {
			authnRequest = null;
			log.error("### authnLoginCert() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnLoginCert() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject authnConnect(HttpServletRequest request)
	{
		JSONObject result = null;

		HttpSession session = request.getSession(false);

		String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");

		// authc : RequestConnectExC
		if (!requestType.equals("connect") && !requestType.equals("authc")) {
			log.error("### RequestType Invalid");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_PARAMETER));
			result.put("message", "RequestType Invalid");
			result.put("data", "");
			return result;
		}

		AuthnRequest authnRequest = getAuthnRequest(session);

		if (authnRequest == null) {
			log.error("### AuthnRequest Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "AuthnRequest Null");
			result.put("data", "");
			return result;
		}

		result = EnvironInform.getInstance().checkLicense(authnRequest.getProviderName());

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		Subject subject = authnRequest.getSubject();

		if (subject == null) {
			authnRequest = null;
			log.error("### AuthnRequest Subject Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_SUBJECT_NULL));
			result.put("message", "AuthnRequest Subject Null");
			result.put("data", "");
			return result;
		}

		NameID nameID = subject.getNameID();

		if (!NameID.ENTITY.equals(nameID.getFormat())) {
			authnRequest = null;
			log.error("### AuthnRequest Subject:NameID Format Invalid");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "AuthnRequest Subject:NameID Format Invalid");
			result.put("data", "");
			return result;
		}

		if (requestType.equals("connect") && !nameID.getValue().equals(SUBJECT_EMPTY_ID)) {
			authnRequest = null;
			log.error("### AuthnRequest Subject:NameID Value Invalid");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "AuthnRequest Subject:NameID Value Invalid");
			result.put("data", "");
			return result;
		}

		String sid = null;
		String spName = authnRequest.getIssuer().getValue();

		byte[] decKey = null;
		byte[] byteData = null;
		String strData = null;
		SSOSecretKey secKey = null;

		try {
			SubjectConfirmationData subjectData = ((SubjectConfirmation) subject.getSubjectConfirmations().get(0)).getSubjectConfirmationData();
			SAMLUtil.checkAndMarshall(subjectData);
			KeyInfo keyInfo = (KeyInfo) subjectData.getUnknownXMLObjects().get(0);

			KeyValue keyValue_0 = (KeyValue) keyInfo.getKeyValues().get(0);
			XSString xsString_0 = (XSString) keyValue_0.getUnknownXMLObject();
			String encData = xsString_0.getValue();

			KeyValue keyValue_1 = (KeyValue) keyInfo.getKeyValues().get(1);
			XSString xsString_1 = (XSString) keyValue_1.getUnknownXMLObject();
			String encKey = xsString_1.getValue();

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			decKey = cryptoApi.decryptPrivateKey(encKey);
			secKey = new SSOSecretKey("SEED", decKey);
			byteData = cryptoApi.decrypt(secKey, encData);
			strData = new String(byteData, "UTF-8");

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(strData);

			String id = (String) jsonData.get("id");
			String appl = (String) jsonData.get("appl");
			sid = (String) jsonData.get("sid");
			String spip = (String) jsonData.get("spip");
			String xid = (String) jsonData.get("xid");
			String xtm = (String) jsonData.get("xtm");

			DateTimeFormatter format = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZoneUTC();
			DateTime issueTime = format.parseDateTime(xtm);

			// 암호키 파기
			Util.zeroize(decKey);
			Util.zeroize(byteData);
			Util.zeroize(strData);
			secKey.finalize();

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AW", "0", spName + "," + Util.getClientIP(request) + ",연계 요청 전송정보 복호화 후 파기,0 으로 덮어쓰기");

			if (!xid.equals(authnRequest.getID())) {
				authnRequest = null;
				log.error("### AuthnRequest ID Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AH", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ID_INVALID));
				result.put("message", "AuthnRequest ID Invalid");
				result.put("data", "");
				return result;
			}

			if (!issueTime.equals(authnRequest.getIssueInstant())) {
				authnRequest = null;
				log.error("### AuthnRequest Issue Time Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AH", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_ISSUE_TIME_INVALID));
				result.put("message", "AuthnRequest Issue Time Invalid");
				result.put("data", "");
				return result;
			}

			if (requestType.equals("connect") && !id.equals(SUBJECT_EMPTY_ID)) {
				authnRequest = null;
				log.error("### AuthnRequest Connect ID Invalid");

				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), (String) result.get("data"),
						"AH", "1", "로그인 패킷 재사용");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
				result.put("message", "AuthnRequest Connect ID Invalid");
				result.put("data", "");
				return result;
			}

			request.setAttribute("applcode", appl);

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						authnRequest = null;
						log.error("### AuthnRequest Subject:IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "AuthnRequest Subject:IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					authnRequest = null;
					log.error("### AuthnRequest Subject:IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "AuthnRequest Subject:IP Empty");
					result.put("data", "");
					return result;
				}
			}

			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String encTKey = (String) session.getAttribute(SESSION_TOKEN_EK);
			String authCode = (String) session.getAttribute(SESSION_AUTHCODE);

			if (Util.isEmpty(encToken) || Util.isEmpty(encKey) || Util.isEmpty(authCode)) {
				authnRequest = null;

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (1)");
				result.put("data", "");
				return result;
			}

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authCode) == null ? null : (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue == null) {
				// 다중화 서버 간 동기화
				authnIssue = getAuthnIssueByEvent(authCode);

				if (authnIssue == null) {
					authnRequest = null;

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
					result.put("message", "SSO Token Null (2)");
					result.put("data", "");
					return result;
				}
			}

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOToken sToken = cryptoApi.decryptToken(encToken, encTKey);
			SSOToken mToken = cryptoApi.decryptToken(mapToken, mapTKey);

			if (sToken == null || mToken == null) {
				authnRequest = null;

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (3)");
				result.put("data", "");
				return result;
			}

			String stHash = cryptoApi.hash(sToken.toString());
			String mtHash = cryptoApi.hash(mToken.toString());

			if (!stHash.equals(mtHash)) {
				authnRequest = null;

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (4)");
				result.put("data", "");
				return result;
			}

			sToken.finalize();
			mToken.finalize();

			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);

			// connect log
			String userId = (String) session.getAttribute("SSO_ID");
			String userIp = Util.getClientIP(request);
			String userBr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

			UserApiFactory.getUserApi().setConnectLog(userId, userIp, userBr, spName);
			Util.setAuditInfo(userId, "AH", "0", userIp + ", " + spName);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
			return result;
		}
		catch (Throwable e) {
			authnRequest = null;
			log.error("### authnConnect() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnConnect() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}
	}

	public JSONObject authnIDPLoginS(HttpServletRequest request, String uid, String upw)
	{
		JSONObject result = null;

		HttpSession session = request.getSession(false);

		if (Util.isEmpty(uid) || Util.isEmpty(upw)) {
			session.removeAttribute("LACHLG");

			log.error("### authnIDPLoginS: Parameter Empty");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.ERR_PARAMETER));
			result.put("message", "Parameter Empty");
			result.put("data", "");
			return result;
		}

		String ch = Util.getAttribute(session, "LACHLG");
		session.removeAttribute("LACHLG");

		if (Util.isEmpty(ch)) {
			log.error("### authnIDPLoginS: CSRFToken Invalid");

			result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DATA_INVALID));
			result.put("message", "Login CSRFToken Invalid");
			result.put("data", "");
			return result;
		}

		try {
			uid = SSOCryptoApi.getInstance().decryptJS(ch, uid);
			upw = SSOCryptoApi.getInstance().decryptJS(ch, upw);
		}
		catch (CryptoApiException e) {
			e.printStackTrace();
			log.error("### authnIDPLoginS: Decrypt Failure");

			result.put("code", String.valueOf(MStatus.AUTH_REQUEST_DECRYPT_FAIL));
			result.put("message", "Login Data Decrypt Failure");
			result.put("data", "");
			return result;
		}

		JSONObject jsonData = (JSONObject) session.getAttribute(ID_AUTHNREQUEST);

		if (jsonData == null) {
			log.error("### authnIDPLoginS: Request Data Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "Request Data Null");
			result.put("data", "");
			return result;
		}

		String spName = (String) jsonData.get("xfr");

		result = EnvironInform.getInstance().checkLicense(spName);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			session.removeAttribute(ID_AUTHNREQUEST);
			jsonData = null;
			return result;
		}

		byte[] decKey = null;
		byte[] byteData = null;
		String strData = null;
		SSOSecretKey secKey = null;

		try {
			String appl = (String) jsonData.get("appl");
			String sid = (String) jsonData.get("sid");
			String spip = (String) jsonData.get("spip");

			request.setAttribute("logintype", "ID_PW");
			request.setAttribute("id", uid);
			request.setAttribute("pw", upw);
			request.setAttribute("spname", spName);
			request.setAttribute("applcode", appl);

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						session.removeAttribute(ID_AUTHNREQUEST);
						jsonData = null;
						log.error("### authnIDPLoginS: AuthnRequest Subject:IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "AuthnRequest Subject:IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					session.removeAttribute(ID_AUTHNREQUEST);
					jsonData = null;
					log.error("### authnIDPLoginS: AuthnRequest Subject:IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "AuthnRequest Subject:IP Empty");
					result.put("data", "");
					return result;
				}
			}

			result = null;
			result = UserApiFactory.getUserApi().login(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);

			request.setAttribute(ID_AUTHNREQUEST, jsonData);
			session.removeAttribute(ID_AUTHNREQUEST);
		}
		catch (Exception e) {
			session.removeAttribute(ID_AUTHNREQUEST);
			jsonData = null;
			log.error("### authnIDPLoginS: Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnIDPLoginS() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject authnLoginS(HttpServletRequest request)
	{
		JSONObject result = null;

		String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");

		if (requestType.equals("connect")) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
			result.put("message", "Not Login State");
			result.put("data", "");
			return result;
		}

		JSONObject jsonData = (JSONObject) request.getAttribute(ID_AUTHNREQUEST);

		if (jsonData == null) {
			log.error("### Request Data Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "Request Data Null");
			result.put("data", "");
			return result;
		}

		String spName = (String) jsonData.get("xfr");

		result = EnvironInform.getInstance().checkLicense(spName);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		byte[] decKey = null;
		byte[] byteData = null;
		String strData = null;
		SSOSecretKey secKey = null;

		try {
			String id = (String) jsonData.get("id");
			String pw = (String) jsonData.get("pw");
			String signedData = (String) jsonData.get("signed");
			String appl = (String) jsonData.get("appl");
			String sid = (String) jsonData.get("sid");
			String spip = (String) jsonData.get("spip");
			String xid = (String) jsonData.get("xid");
			String xtm = (String) jsonData.get("xtm");

			if (Util.isEmpty(signedData)) {
				request.setAttribute("logintype", "ID_PW");
				request.setAttribute("id", id);
				request.setAttribute("pw", pw);
			}
			else {
				request.setAttribute("logintype", "CERT");
				request.setAttribute("signed", signedData);
			}

			request.setAttribute("spname", spName);
			request.setAttribute("applcode", appl);

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						jsonData = null;
						log.error("### AuthnRequest Subject:IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "AuthnRequest Subject:IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					jsonData = null;
					log.error("### AuthnRequest Subject:IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "AuthnRequest Subject:IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// 로그인
			result = null;

			if (Util.isEmpty(signedData)) {
				result = UserApiFactory.getUserApi().login(request);
			}
			else {
				result = UserApiFactory.getUserApi().loginCert(request);
			}

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			HttpSession session = request.getSession(false);
			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);

//			log.debug("### Check DupLogin : " + MemConfig.getInstance().getDupLoginType());
//
//			// 중복로그인 체크 (0:허용, 1:선입자우선, 2:후입자우선)
//			if (!MemConfig.getInstance().getDupLoginType().equals("0")) {
//				// 기존 동일 사용자로 로그인한 정보가 있다면 삭제(중복로그인 방지)
//				logoutRequestToOther(request);
//			}
		}
		catch (Exception e) {
			jsonData = null;
			log.error("### authnLogin() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnLogin() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject authnConnectS(HttpServletRequest request)
	{
		String requestType = request.getParameter("RequestType") == null ? "" : request.getParameter("RequestType");

		if (requestType.equals("connectExM")) {  // Mobile App to Web
			return authnConnectExM(request);
		}

		JSONObject result = null;

		HttpSession session = request.getSession(false);
		JSONObject jsonData = (JSONObject) request.getAttribute(ID_AUTHNREQUEST);

		if (jsonData == null) {
			log.error("### Request Data Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "Request Data Null");
			result.put("data", "");
			return result;
		}

		String id = (String) jsonData.get("id");
		String sid = (String) jsonData.get("sid");
		String spip = (String) jsonData.get("spip");
		String spName = (String) jsonData.get("xfr");

		if (requestType.equals("connect") && !id.equals(SUBJECT_EMPTY_ID)) {
			request.removeAttribute(ID_AUTHNREQUEST);
			log.error("### AuthnRequest ID Value Invalid");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "AuthnRequest ID Value Invalid");
			result.put("data", "");
			return result;
		}

		result = EnvironInform.getInstance().checkLicense(spName);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			request.removeAttribute(ID_AUTHNREQUEST);
			return result;
		}

		try {
			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						request.removeAttribute(ID_AUTHNREQUEST);
						log.error("### AuthnRequest IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "AuthnRequest IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					request.removeAttribute(ID_AUTHNREQUEST);
					log.error("### AuthnRequest IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "AuthnRequest IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// 연계
			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String encTKey = (String) session.getAttribute(SESSION_TOKEN_EK);
			String authCode = (String) session.getAttribute(SESSION_AUTHCODE);

			if (Util.isEmpty(encToken) || Util.isEmpty(encTKey) || Util.isEmpty(authCode)) {
				request.removeAttribute(ID_AUTHNREQUEST);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (1)");
				result.put("data", "");
				return result;
			}

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authCode) == null ? null : (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue == null) {
				// 다중화 서버 간 동기화
				authnIssue = getAuthnIssueByEvent(authCode);

				if (authnIssue == null) {
					request.removeAttribute(ID_AUTHNREQUEST);

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
					result.put("message", "SSO Token Null (2)");
					result.put("data", "");
					return result;
				}
			}

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			SSOToken sToken = cryptoApi.decryptToken(encToken, encTKey);
			SSOToken mToken = cryptoApi.decryptToken(mapToken, mapTKey);

			if (sToken == null || mToken == null) {
				request.removeAttribute(ID_AUTHNREQUEST);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (3)");
				result.put("data", "");
				return result;
			}

			String stHash = cryptoApi.hash(sToken.toString());
			String mtHash = cryptoApi.hash(mToken.toString());

			if (!stHash.equals(mtHash)) {
				request.removeAttribute(ID_AUTHNREQUEST);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (4)");
				result.put("data", "");
				return result;
			}

			sToken.finalize();
			mToken.finalize();

			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);

			// connect log
			String userId = (String) session.getAttribute("SSO_ID");
			String userIp = Util.getClientIP(request);
			String userBr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

			UserApiFactory.getUserApi().setConnectLog(userId, userIp, userBr, spName);
			Util.setAuditInfo(userId, "AH", "0", userIp + ", " + spName);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
			return result;
		}
		catch (Throwable e) {
			jsonData = null;
			log.error("### authnConnect() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnConnect() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}
	}

	public JSONObject authnConnectExM(HttpServletRequest request)
	{
		JSONObject result = null;

		HttpSession session = request.getSession(false);
		JSONObject jsonData = (JSONObject) request.getAttribute(ID_AUTHNREQUEST);

		if (jsonData == null) {
			log.error("### Request Data Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "IDP authnConnectExM: Request Data Null");
			result.put("data", "");
			return result;
		}

		String spip = (String) jsonData.get("spip");
		String spName = (String) jsonData.get("xfr");

		result = EnvironInform.getInstance().checkLicense(spName);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			request.removeAttribute(ID_AUTHNREQUEST);
			return result;
		}

		try {
			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spName);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						request.removeAttribute(ID_AUTHNREQUEST);
						log.error("### AuthnRequest IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "IDP authnConnectExM: AuthnRequest IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					request.removeAttribute(ID_AUTHNREQUEST);
					log.error("### AuthnRequest IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "IDP authnConnectExM: AuthnRequest IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// 연계
			String userId = (String) jsonData.get("id");
			String authCode = (String) jsonData.get("authcode");
			//String blockid = (String) reqData.get("blockid");
			String sid = (String) jsonData.get("sid");

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authCode) == null ? null : (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue == null) {
				// 다중화 서버 간 동기화
				authnIssue = getAuthnIssueByEvent(authCode);

				if (authnIssue == null) {
					request.removeAttribute(ID_AUTHNREQUEST);

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
					result.put("message", "IDP authnConnectExM: Token Null(1)");
					result.put("data", "");
					return result;
				}
			}

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			SSOToken mToken = cryptoApi.decryptToken(mapToken, mapTKey);

			if (mToken == null) {
				request.removeAttribute(ID_AUTHNREQUEST);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "IDP authnConnectExM: Token Null(2)");
				result.put("data", "");
				return result;
			}

			session.setAttribute(CommonProvider.SESSION_SSO_ID, userId);
			session.setAttribute(CommonProvider.SESSION_TOKEN_EK, mapTKey);
			session.setAttribute(CommonProvider.SESSION_TOKEN, mapToken);

			mToken.finalize();

			session.setAttribute(spName + SUFFIX_SP_SESSION, sid);

			// connect log
			String userIp = Util.getClientIP(request);
			String userBr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

			UserApiFactory.getUserApi().setConnectLog(userId, userIp, userBr, spName);
			Util.setAuditInfo(userId, "AH", "0", userIp + ", " + spName);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
			return result;
		}
		catch (Throwable e) {
			jsonData = null;
			log.error("### authnConnectExM() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7014));
			result.put("message", "IDP authnConnectExM Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}
	}

	public JSONObject authnDominoLoginS(HttpServletRequest request)
	{
		JSONObject result = null;

		String spName = "SP_DOMINO";
		String uid = request.getParameter("loginId");
		String upw = request.getParameter("loginPw");
		String logout = (String) request.getAttribute("logout");

		try {
			request.setAttribute("logintype", "ID_PW");
			request.setAttribute("id", uid);
			request.setAttribute("pw", upw);
			request.setAttribute("spname", spName);
			request.setAttribute("applcode", "APPLDEFAULT");

			result = UserApiFactory.getUserApi().login(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			HttpSession session = request.getSession(false);
			session.setAttribute(spName + SUFFIX_SP_SESSION, logout);
		}
		catch (Exception e) {
			log.error("### authnLogin() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnLogin() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject authnDominoConnectS(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();

		String spName = "SP_DOMINO";
		String logout = (String) request.getAttribute("logout");

		try {
			HttpSession session = request.getSession(false);

			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String encTKey = (String) session.getAttribute(SESSION_TOKEN_EK);
			String authCode = (String) session.getAttribute(SESSION_AUTHCODE);

			if (Util.isEmpty(encToken) || Util.isEmpty(encTKey) || Util.isEmpty(authCode)) {
				log.error("### SSO Token Null (1)");

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (1)");
				result.put("data", "");
				return result;
			}

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authCode) == null ? null : (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue == null) {
				// 다중화 서버 간 동기화
				authnIssue = getAuthnIssueByEvent(authCode);

				if (authnIssue == null) {
					log.error("### SSO Token Null (2)");

					result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
					result.put("message", "SSO Token Null (2)");
					result.put("data", "");
					return result;
				}
			}

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			SSOToken sToken = cryptoApi.decryptToken(encToken, encTKey);
			SSOToken mToken = cryptoApi.decryptToken(mapToken, mapTKey);

			if (sToken == null || mToken == null) {
				log.error("### SSO Token Null (3)");

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (3)");
				result.put("data", "");
				return result;
			}

			String stHash = cryptoApi.hash(sToken.toString());
			String mtHash = cryptoApi.hash(mToken.toString());

			if (!stHash.equals(mtHash)) {
				log.error("### SSO Token Null (4)");

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (4)");
				result.put("data", "");
				return result;
			}

			sToken.finalize();
			mToken.finalize();

			session.setAttribute(spName + SUFFIX_SP_SESSION, logout);

			// connect log
			String userId = (String) session.getAttribute("SSO_ID");
			String userIp = Util.getClientIP(request);
			String userBr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

			UserApiFactory.getUserApi().setConnectLog(userId, userIp, userBr, spName);
			Util.setAuditInfo(userId, "AH", "0", userIp + ", " + spName);

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### authnConnect() Exception: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnConnect() Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject authnSiluetConnectS(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();

		String spName = "SP_SILUET";
		String logout = (String) request.getAttribute("logout");

		try {
			HttpSession session = request.getSession(false);

			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String encTKey = (String) session.getAttribute(SESSION_TOKEN_EK);
			String authCode = (String) session.getAttribute(SESSION_AUTHCODE);

			if (Util.isEmpty(encToken) || Util.isEmpty(encTKey) || Util.isEmpty(authCode)) {
				log.error("### SSO Token Null (1)");

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (1)");
				result.put("data", "");
				return result;
			}

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authCode) == null ? null : (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue == null) {
				// 다중화 서버 간 동기화
				authnIssue = getAuthnIssueByEvent(authCode);

				if (authnIssue == null) {
					log.error("### SSO Token Null (2)");

					result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
					result.put("message", "SSO Token Null (2)");
					result.put("data", "");
					return result;
				}
			}

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			SSOToken sToken = cryptoApi.decryptToken(encToken, encTKey);
			SSOToken mToken = cryptoApi.decryptToken(mapToken, mapTKey);

			if (sToken == null || mToken == null) {
				log.error("### SSO Token Null (3)");

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (3)");
				result.put("data", "");
				return result;
			}

			String stHash = cryptoApi.hash(sToken.toString());
			String mtHash = cryptoApi.hash(mToken.toString());

			if (!stHash.equals(mtHash)) {
				log.error("### SSO Token Null (4)");

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (4)");
				result.put("data", "");
				return result;
			}

			sToken.finalize();
			mToken.finalize();

			session.setAttribute(spName + SUFFIX_SP_SESSION, logout);

			// connect log
			String userId = (String) session.getAttribute("SSO_ID");
			String userIp = Util.getClientIP(request);
			String userBr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

			UserApiFactory.getUserApi().setConnectLog(userId, userIp, userBr, spName);
			Util.setAuditInfo(userId, "AH", "0", userIp + ", " + spName);

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		catch (Throwable e) {
			log.error("### authnConnect() Exception: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_INVALID));
			result.put("message", "authnConnect() Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject generateResponse(HttpServletRequest request)
	{
		JSONObject result = null;
		HttpSession session = request.getSession(true);

		AuthnRequest authnRequest = getAuthnRequest(session);

		if (authnRequest == null) {
			log.error("### AuthnRequest Null");

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "AuthnRequest Null");
			result.put("data", "");
			return result;
		}

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String encKey = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
			authnRequest = null;

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
			result.put("message", "SSO Token Null (1)");
			result.put("data", "");
			return result;
		}

		SSOToken token;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, encKey);

			if (token == null) {
				authnRequest = null;

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (2)");
				result.put("data", "");
				return result;
			}

		}
		catch (CryptoApiException e) {
			log.error("### SSOCryptoApi.getInstance() CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "SSOCryptoApi.getInstance() CryptoApiException: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		String authnContextClass = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).getAuthnContextClassRef();

		result = generateResponse(session, token, Util.getClientIP(request), authnRequest.getProviderName(),
				authnRequest.getID(), authnRequest.getIssueInstant(), authnContextClass);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		// 연계정보: 연계 시 사용
		session.setAttribute(ID_AUTHSESSION, SessionManager.getInstance().getSession(token.getId()));

		try { token.finalize(); } catch (Throwable e) {}

		return result;
	}

	public JSONObject generateResponseS(HttpServletRequest request)
	{
		JSONObject result = null;
		HttpSession session = request.getSession(true);

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String encKey = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
			result.put("message", "SSO Token Null (1)");
			result.put("data", "");
			return result;
		}

		SSOToken token;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, encKey);

			if (token == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (2)");
				result.put("data", "");
				return result;
			}
		}
		catch (CryptoApiException e) {
			log.error("### SSOCryptoApi.getInstance() CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "SSOCryptoApi.getInstance() CryptoApiException: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		result = generateResponseS(request, token);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		// 연계정보: 연계 시 사용
		session.setAttribute(ID_AUTHSESSION, SessionManager.getInstance().getSession(token.getId()));

		try { token.finalize(); } catch (Throwable e) {}

		return result;
	}

	public JSONObject generatePythonResponseS(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			HttpSession session = request.getSession(true);

			String usrId = (String) session.getAttribute(SESSION_SSO_ID);
			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String encKey = (String) session.getAttribute(SESSION_TOKEN_EK);

			if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
				log.error("### generatePythonResponseS: Empty Token");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (1)");
				result.put("data", "");
				return result;
			}

			SSOToken token;

			token = SSOCryptoApi.getInstance().decryptToken(encToken, encKey);

			if (token == null) {
				log.error("### generatePythonResponseS: Token Decrypt Fail");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (2)");
				result.put("data", "");
				return result;
			}

			String spName = request.getAttribute("spName") == null ? "" : (String) request.getAttribute("spName");
			String relay = "";
			String query = request.getQueryString() == null ? "" : request.getQueryString();

			int idx = query.indexOf("RelayState=");
			if (idx >= 0) {
				relay = query.substring(idx + "RelayState=".length());

				SPSSODescriptor spDesc = MetadataRepository.getInstance().getSPDescriptor(spName);

				if (!checkEndpoint(relay, spDesc)) {
					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_RELAYSTATE_NOT_MATCH));
					result.put("message", "RelayState not matched");
					result.put("data", "");
					return result;
				}
			}

			JSONObject sData = new JSONObject();
			sData.put("token", token.toJsonString());
			sData.put("relay", relay);
			sData.put("xid", Util.generateUUID());

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(sData, spName);

			// sessionMap Add
			AuthSession authSession = SessionManager.getInstance().getSession(usrId);
			authSession.addRemoteSessionByS2S(usrId, spName, new DateTime(DateTimeZone.UTC), AuthnContext.PASSWORD_AUTHN_CTX,
					(String) session.getAttribute(spName + SUFFIX_SP_SESSION));

			// connect log
			String userId = (String) session.getAttribute("SSO_ID");
			String userIp = Util.getClientIP(request);
			String userBr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

			UserApiFactory.getUserApi().setConnectLog(userId, userIp, userBr, spName);
			Util.setAuditInfo(userId, "AH", "0", userIp + ", " + spName);

			try { token.finalize(); } catch (Throwable e) {}

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encData);

			log.info("### Python Response Data: {}", encData);
		}
		catch (CryptoApiException e) {
			log.error("### generatePythonResponseS: CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generatePythonResponseS: CryptoApiException: " + e.getMessage());
			result.put("data", "");
		}
		catch (SSOException e) {
			log.error("### generatePythonResponseS: SSOException: {}, {}", e.getErrorCode(), e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generatePythonResponseS: SSOException: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject generateResponse(HttpSession session, SSOToken token, String userIp, String spName,
			String authnID, DateTime authnIssue, String authnContextClass)
	{
		JSONObject result = new JSONObject();

		try {
			String userId = token.getId();

			String xid = SAMLUtil.createSamlId("IDP-");
			DateTime issueTime = new DateTime(DateTimeZone.UTC);
			String xtime = issueTime.toString("yyyy-MM-dd'T'HH:mm:ss.SSS");

			JSONObject sData = new JSONObject();
			sData.put("idpsession", session.getId());
			sData.put("token", token.getTokenValue().toString());
			sData.put("xid", xid);
			sData.put("xtm", xtime);

			String encData = Util.encode64(sData.toString().getBytes("UTF-8"));

			// SAML Response
			Response samlResponse = SAMLUtil.makeResponse(authnID, xid, issueTime);
			samlResponse.setIssuer(SAMLUtil.makeIssuer(serverName));

			// SAML Assertion
			Assertion assertion = (Assertion) SAMLUtil.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
			assertion.setID(xid);
			assertion.setIssueInstant(issueTime);

			assertion.setIssuer(SAMLUtil.makeIssuer(serverName));
			assertion.setSubject(SAMLUtil.makeSubject(userId, authnID));
			assertion.setConditions(SAMLUtil.makeConditions(issueTime));
			assertion.getAuthnStatements().add(SAMLUtil.makeAuthnStatement(authnIssue, authnContextClass));
			assertion.getAttributeStatements().add(SAMLUtil.makeAttributeStatement(encData));
			//assertion.getAttributeStatements().add(SAMLUtil.makeAttributeStatement(token, session.getId()));

			SPSSODescriptor entityDescriptor = MetadataRepository.getInstance().getSPDescriptor(spName);

			if (entityDescriptor.getWantAssertionsSigned().booleanValue()) {
				SSOCryptoApi.getInstance().generateSignedXML(assertion);
			}

			log.debug("### Assertion XML:\n{}", Util.domToStr(assertion.getDOM().getOwnerDocument(), true));

			// sessionMap Add
			AuthSession authSession = SessionManager.getInstance().getSession(userId);
			authSession.addRemoteSessionByAssertion(userId, spName, assertion,
					(String) session.getAttribute(spName + SUFFIX_SP_SESSION));

			boolean encrytped = true;

			if (encrytped) {
				EncryptedAssertion encryptAsst = SSOCryptoApi.getInstance().getEncryptedAssertion(userIp, spName, assertion);
				samlResponse.getEncryptedAssertions().add(encryptAsst);
			}
			else {
				samlResponse.getAssertions().add(assertion);
			}

			SAMLUtil.checkAndMarshall(samlResponse);

			log.debug("### samlResponse XML:\n{}", Util.domToStr(samlResponse.getDOM().getOwnerDocument(), true));

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", samlResponse);
		}
		catch (CryptoApiException e) {
			log.error("### addAssertion() CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "addAssertion() CryptoApiException: " + e.getMessage());
			result.put("data", "");
		}
		catch (SSOException e) {
			log.error("### addAssertion() SSOException: {}, {}", e.getErrorCode(), e.getMessage());

			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "addAssertion() SSOException: " + e.getMessage());
			result.put("data", "");
		}
		catch (Exception e) {
			log.error("### addAssertion() Exception: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "addAssertion() Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject generateResponseS(HttpServletRequest request, SSOToken token)
	{
		JSONObject result = new JSONObject();
		HttpSession session = request.getSession(true);

		JSONObject jsonData = (JSONObject) request.getAttribute(ID_AUTHNREQUEST);

		if (jsonData == null) {
			log.error("### Request Data Null");

			result.put("code", String.valueOf(MStatus.AUTH_REQ_NULL));
			result.put("message", "Request Data Null");
			result.put("data", "");
			return result;
		}

		String reqId = (String) jsonData.get("id");
		String usrId = token.getId();

		if (!Util.isEmpty(reqId) && !reqId.equals(SUBJECT_EMPTY_ID) && !usrId.equals(reqId)) {
			log.error("### Authentication User ID Mismatch");

			result.put("code", String.valueOf(MStatus.AUTH_USER_ID_NOT_MATCH));
			result.put("message", "Authentication User ID Mismatch");
			result.put("data", "");
			return result;
		}

		try {
			String spName = (String) jsonData.get("xfr");
			String xid = (String) jsonData.get("xid");
			String relay = (String) jsonData.get("relay");
			String tid = Util.generateUUID();

			JSONObject sData = new JSONObject();
			sData.put("auid", xid);
			sData.put("relay", relay);
			sData.put("sid", session.getId());
			sData.put("token", token.getTokenValue().toString());
			sData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(sData, spName);

			// sessionMap Add
			AuthSession authSession = SessionManager.getInstance().getSession(usrId);
			authSession.addRemoteSessionByS2S(usrId, spName, new DateTime(DateTimeZone.UTC), AuthnContext.PASSWORD_AUTHN_CTX,
					(String) session.getAttribute(spName + SUFFIX_SP_SESSION));

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encData);
		}
		catch (CryptoApiException e) {
			log.error("### addAssertion() CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "addAssertion() CryptoApiException: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject generateDominoResponseS(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();
		HttpSession session = request.getSession(true);

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String encKey = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
			result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
			result.put("message", "SSO Token Null (1)");
			result.put("data", "");
			return result;
		}

		SSOToken token;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, encKey);

			if (token == null) {
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (2)");
				result.put("data", "");
				return result;
			}

			String user_cn = (String) request.getAttribute("cn");
			String user_ou = (String) request.getAttribute("ou");
			String user_o = (String) request.getAttribute("o");

			StringBuilder userInfo = new StringBuilder();
			userInfo.append("CN=").append(token.getProperty(user_cn));
			if (!Util.isEmpty(user_ou))  userInfo.append(",OU=").append(token.getProperty(user_ou));
			userInfo.append(",O=").append(token.getProperty(user_o));

			String ltpaToken = LtpaToken.generateLtpa2Token(userInfo.toString());

			// 연계정보: 연계 시 사용
			session.setAttribute(ID_AUTHSESSION, SessionManager.getInstance().getSession(token.getId()));

			try { token.finalize(); } catch (Throwable e) {}

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", ltpaToken);
		}
		catch (Exception e) {
			log.error("### generateDominoResponseS() Exception: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.AUTH_EXCEPTION));
			result.put("message", "generateDominoResponseS() Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject generateSiluetResponseS(HttpServletRequest request)
	{
		JSONObject result = new JSONObject();
		HttpSession session = request.getSession(true);

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String encKey = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
			result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
			result.put("message", "SSO Token Null (1)");
			result.put("data", "");
			return result;
		}

		SSOToken token;

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			token = crypto.decryptToken(encToken, encKey);

			if (token == null) {
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (2)");
				result.put("data", "");
				return result;
			}

			String userInfo = token.toJsonString();

			String siluetToken = LtpaToken.generateSiluetToken(userInfo);

			// 연계정보: 연계 시 사용
			session.setAttribute(ID_AUTHSESSION, SessionManager.getInstance().getSession(token.getId()));

			try { token.finalize(); } catch (Throwable e) {}

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", siluetToken);
		}
		catch (Exception e) {
			log.error("### generateSiluetResponseS() Exception: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.AUTH_EXCEPTION));
			result.put("message", "generateSiluetResponseS() Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject generateGitlabResponse(HttpServletRequest request)
	{
		JSONObject result = null;
		HttpSession session = request.getSession(false);

		String spName = (String) request.getAttribute("spName");
		String authnID = (String) request.getAttribute("authnID");
		DateTime authnIssueTime = (DateTime) request.getAttribute("authnIssueTime");

		if (Util.isEmpty(spName) || Util.isEmpty(authnID) || authnIssueTime == null) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
			result.put("message", "Empty parameter");
			result.put("data", "");
			return result;
		}

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String encKey = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
			result.put("message", "SSO Token Null (1)");
			result.put("data", "");
			return result;
		}

		SSOToken token;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, encKey);

			if (token == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (2)");
				result.put("data", "");
				return result;
			}
		}
		catch (CryptoApiException e) {
			log.error("### generateGitlabResponse: CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateGitlabResponse: CryptoApiException: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		result = generateGitlabResponse(session, token, spName, authnID, authnIssueTime);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		try { token.finalize(); } catch (Throwable e) {}

		return result;
	}

	public JSONObject generateGitlabResponse(HttpSession session, SSOToken token, String spName, String authnID, DateTime authnIssueTime)
	{
		JSONObject result = new JSONObject();

		try {
			String userId = token.getId();

			SPSSODescriptor spDes = MetadataRepository.getInstance().getSPDescriptor(spName);
			String spEndpoint = spDes.getDefaultAssertionConsumerService().getLocation();
			String nameIDType = spDes.getNameIDFormats().get(0).getFormat();
			List<RequestedAttribute> attributeList = spDes.getAttributeConsumingServices().get(0).getRequestAttributes();
			log.debug("### spEndpoint: {}: {}: {}", spName, spEndpoint, nameIDType);

			String resid = SAMLUtil.createSamlId("_");
			String xid = SAMLUtil.createSamlId("_");
			DateTime issueTime = new DateTime(DateTimeZone.UTC);

			// SAML Response
			Response samlResponse = SAMLUtil.makeStdResponse(resid, issueTime, spEndpoint, authnID);
			samlResponse.setIssuer(SAMLUtil.makeStdIssuer(serverName));
			samlResponse.setStatus(SAMLUtil.makeStatus(StatusCode.SUCCESS_URI));

			// SAML Assertion
			Assertion assertion = SAMLUtil.makeStdAssertion(xid, issueTime);
			assertion.setIssuer(SAMLUtil.makeStdIssuer(serverName));
			assertion.setSubject(SAMLUtil.makeStdSubject(userId, nameIDType, issueTime, spEndpoint, serverName, spName, authnID, null));
			assertion.setConditions(SAMLUtil.makeStdConditions(issueTime, spName));
			assertion.getAuthnStatements().add(SAMLUtil.makeStdAuthnStatement(authnIssueTime));
			assertion.getAttributeStatements().add(SAMLUtil.makeStdAttributeStatement(attributeList, token));

			SPSSODescriptor entityDescriptor = MetadataRepository.getInstance().getSPDescriptor(spName);

			if (entityDescriptor.getWantAssertionsSigned().booleanValue()) {
				SSOCryptoApi.getInstance().generateStdSignedXML(assertion);
			}

			samlResponse.getAssertions().add(assertion);

			if (!entityDescriptor.getWantAssertionsSigned().booleanValue()) {
				SSOCryptoApi.getInstance().generateStdSignedXML(samlResponse);
			}

			SAMLUtil.checkAndMarshall(samlResponse);
			log.debug("### samlResponse XML:\n{}", Util.domToStr(samlResponse.getDOM().getOwnerDocument(), true));

			// sessionMap Add
			AuthSession authSession = SessionManager.getInstance().getSession(userId);
			authSession.addRemoteSessionByAssertion(userId, spName, assertion,
					(String) session.getAttribute(spName + SUFFIX_SP_SESSION));

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", samlResponse);
		}
		catch (CryptoApiException e) {
			log.error("### generateGitlabResponse: CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateGitlabResponse: CryptoApiException: " + e.getMessage());
			result.put("data", "");
		}
		catch (SSOException e) {
			log.error("### generateGitlabResponse: SSOException: {}, {}", e.getErrorCode(), e.getMessage());

			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generateGitlabResponse: SSOException: " + e.getMessage());
			result.put("data", "");
		}
		catch (Exception e) {
			log.error("### generateGitlabResponse: Exception: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "generateGitlabResponse: Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}
	
	public JSONObject generateM365Response(HttpServletRequest request)
	{
		JSONObject result = null;
		HttpSession session = request.getSession(false);

		String spName = (String) request.getAttribute("spName");
		String authnID = (String) request.getAttribute("authnID");

		DateTime authnIssueTime = (DateTime) request.getAttribute("authnIssueTime");

		if (Util.isEmpty(spName) || Util.isEmpty(authnID) || authnIssueTime == null) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
			result.put("message", "Empty parameter");
			result.put("data", "");
			return result;
		}

		String encToken = (String) session.getAttribute(SESSION_TOKEN);
		String encKey = (String) session.getAttribute(SESSION_TOKEN_EK);

		if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
			result.put("message", "SSO Token Null (1)");
			result.put("data", "");
			return result;
		}

		SSOToken token;

		try {
			token = SSOCryptoApi.getInstance().decryptToken(encToken, encKey);

			if (token == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "SSO Token Null (2)");
				result.put("data", "");
				return result;
			}
		}
		catch (CryptoApiException e) {
			log.error("### generateM365Response: CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateM365Response: CryptoApiException: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		result = generateM365Response(session, token, spName, authnID, authnIssueTime);

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			return result;
		}

		try { token.finalize(); } catch (Throwable e) {}

		return result;
	}

	public JSONObject generateM365Response(HttpSession session, SSOToken token, String spName, String authnID, DateTime authnIssueTime)
	{
		JSONObject result = new JSONObject();

		try {
			SSOConfig config = SSOConfig.getInstance();
			String userId = token.getId();
			SPSSODescriptor spDes = MetadataRepository.getInstance().getSPDescriptor(spName);
			String spEndpoint = spDes.getDefaultAssertionConsumerService().getLocation();
			String nameIDType = spDes.getNameIDFormats().get(0).getFormat();
			String issuer = config.getString("m365.issuer", "");
			String aud = config.getString("m365.aud", "urn:federation:MicrosoftOnline");
			String immutableID = token.getProperty("IMMUTABLEID");

			List<RequestedAttribute> attributeList = spDes.getAttributeConsumingServices().get(0).getRequestAttributes();
			log.debug("### spEndpoint: {}: {}: {}", spName, spEndpoint, nameIDType);

			String resid = SAMLUtil.createSamlId("_");
			String xid = SAMLUtil.createSamlId("_");
			DateTime issueTime = new DateTime(DateTimeZone.UTC);

			// SAML Response
			Response samlResponse = SAMLUtil.makeStdResponse(resid, issueTime, spEndpoint, authnID);
			samlResponse.setIssuer(SAMLUtil.makeStdIssuer(issuer));
			samlResponse.setStatus(SAMLUtil.makeStatus(StatusCode.SUCCESS_URI));

			// SAML Assertion
			Assertion assertion = SAMLUtil.makeStdAssertion(xid, issueTime);
			assertion.setIssuer(SAMLUtil.makeStdIssuer(issuer));
			assertion.setSubject(SAMLUtil.makeStdSubject(userId, nameIDType, issueTime, spEndpoint, issuer, spName, authnID, immutableID));
			assertion.setConditions(SAMLUtil.makeStdConditions(issueTime, aud));
			assertion.getAuthnStatements().add(SAMLUtil.makeStdAuthnStatement(authnIssueTime));
			assertion.getAttributeStatements().add(SAMLUtil.makeStdAttributeStatement(attributeList, token));

			SPSSODescriptor entityDescriptor = MetadataRepository.getInstance().getSPDescriptor(spName);

			if (entityDescriptor.getWantAssertionsSigned().booleanValue()) {
				SSOCryptoApi.getInstance().generateStdSignedXML(assertion);
			}

			samlResponse.getAssertions().add(assertion);

			if (!entityDescriptor.getWantAssertionsSigned().booleanValue()) {
				SSOCryptoApi.getInstance().generateStdSignedXML(samlResponse);
			}

			SAMLUtil.checkAndMarshall(samlResponse);
			log.debug("### samlResponse XML:\n{}", Util.domToStr(samlResponse.getDOM().getOwnerDocument(), true));

			// sessionMap Add
			AuthSession authSession = SessionManager.getInstance().getSession(userId);
			authSession.addRemoteSessionByAssertion(userId, spName, assertion,
					(String) session.getAttribute(spName + SUFFIX_SP_SESSION));

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", samlResponse);
		}
		catch (CryptoApiException e) {
			log.error("### generateM365Response: CryptoApiException: {}, {}", e.getCode(), e.getMessage());

			result.put("code", String.valueOf(e.getCode()));
			result.put("message", "generateM365Response: CryptoApiException: " + e.getMessage());
			result.put("data", "");
		}
		catch (SSOException e) {
			log.error("### generateM365Response: SSOException: {}, {}", e.getErrorCode(), e.getMessage());

			result.put("code", String.valueOf(e.getErrorCode()));
			result.put("message", "generateM365Response: SSOException: " + e.getMessage());
			result.put("data", "");
		}
		catch (Exception e) {
			log.error("### generateM365Response: Exception: {}", e.getMessage());

			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "generateM365Response: Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public AuthnIssue getAuthnIssueByEvent(String authCode)
	{
		SyncMonitor.startMonitor();

		if (!SyncMonitor.isReady()) {
			return null;
		}

		SyncMonitor.requestAuthcodeEvent(authCode);

		int waitCount = 3;
		while (waitCount != 0) {
			try {
				Thread.sleep(200);
			}
			catch (InterruptedException e) {
				e.printStackTrace();
				return null;
			}

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authCode) == null ? null : (AuthnIssue) authcodeMap.get(authCode);

			if (authnIssue == null) {
				waitCount--;
				continue;
			}
			else {
				return authnIssue;
			}
		}

		return null;
	}

	public String getSPLogoutInfo(HttpServletRequest request)
	{
		ArrayList<String> resultList = new ArrayList<String>();

		HttpSession session = request.getSession(true);
		Enumeration<?> em = session.getAttributeNames();

		while (em.hasMoreElements()) {
			String skey = (String) em.nextElement();
			int ii = skey.indexOf("^^^SESS_ID");

			if (ii >= 0) {
				String provider = skey.substring(0, ii);

				if (provider.indexOf("IDP") >= 0)
					continue;

				String location = getSPLogoutLocation(provider);

				if (Util.isEmpty(location.trim()))
					continue;

				resultList.add(location);
			}
		}

		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i < resultList.size(); i++) {
			String temp = (String) resultList.get(i);
			int idx = temp.indexOf("/Logout.");
			buffer.append(temp.substring(0, idx)).append("/LogoutEx.").append(temp.substring(idx + 8));

			if ((i + 1) < resultList.size())
				buffer.append("^");
		}

		// Oidc Logout
		String rootAuthSessionId = (String) session.getAttribute("DS_SESSION_ID");
		RootAuthSession rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);

		if (rootAuthSession == null) {
			rootAuthSession = getRootAuthSessionByEvent(rootAuthSessionId);
		}

		if (rootAuthSession != null) {
			List<String> logoutUrls = rootAuthSession.getLogoutUrls();
			if (logoutUrls != null) {
				for (int i = 0; i < logoutUrls.size(); i++) {
					if (resultList.size() > 0) {
						buffer.append("^");
					}
					buffer.append(logoutUrls.get(i));
					if ((i + 1) < logoutUrls.size())
						buffer.append("^");
				}
			}
		}

		// Domino Logout
		String dominoLogout = (String) session.getAttribute("SP_DOMINO^^^SESS_ID");

		if (!Util.isEmpty(dominoLogout)) {
			if (resultList.size() > 0) {
				buffer.append("^");
			}

			buffer.append(dominoLogout);
		}

		// Siluet Logout
		String siluetLogout = (String) session.getAttribute("SP_SILUET^^^SESS_ID");

		if (!Util.isEmpty(dominoLogout)) {
			if (resultList.size() > 0) {
				buffer.append("^");
			}

			buffer.append(dominoLogout);
		}

		return buffer.toString();
	}

	public String getSPLogoutLocation(String provider)
	{
		SPSSODescriptor spDescriptor;

		try {
			spDescriptor = MetadataRepository.getInstance().getSPDescriptor(provider);
		}
		catch (SSOException e) {
			e.printStackTrace();
			return "";
		}

		List<SingleLogoutService> services = spDescriptor.getSingleLogoutServices();

		for (int i = 0; i < services.size(); i++) {
			SingleLogoutService service = (SingleLogoutService) services.get(i);
			return service.getLocation();
		}

		return "";
	}

	public void setLogoutInfo(HttpServletRequest request, String spName, String br, String dupinfo)
	{
		try {
			HttpSession session = request.getSession(false);

			String encToken = session.getAttribute(SESSION_TOKEN) == null ? "" : (String) session.getAttribute(SESSION_TOKEN);
			String encKey = session.getAttribute(SESSION_TOKEN_EK) == null ? "" : (String) session.getAttribute(SESSION_TOKEN_EK);

			if (Util.isEmpty(encToken) || Util.isEmpty(encKey)) {
				return;
			}

			SSOToken token = null;

			try {
				token = SSOCryptoApi.getInstance().decryptToken(encToken, encKey);
			}
			catch (Exception e) {
				token = null;
			}

			if (token == null) {
				return;
			}

			String id = token.getId();
			String ip = (String) Util.getClientIP(request);
			String loginType = token.getProperty("LOGIN_TYPE");

			UserApi userApi = UserApiFactory.getUserApi();

			userApi.clearLoginIP(id, ip, br);
			userApi.clearIpInfo(id, ip, br);
			userApi.setLogoutLog(id, ip, br, loginType, spName);

			//Util.zeroize(encToken);
			//Util.zeroize(encKey);

			if (!Util.isEmpty(dupinfo)) {
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), id, "AJ", "0",
						"login(" + dupinfo + "), " + spName);
			}

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), id, "BD", "0", ip);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Mobile
	public JSONObject smartLogin(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### 인증 비활성화 상태");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

			if (Util.isEmpty(encData)) {
				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_REQ_PARAMETER));
				result.put("message", "IDP smartLogin: Empty parameter");
				result.put("data", "");
				return result;
			}

			// Decrypt Data
			JSONObject jsonData = SSOCryptoApi.getInstance().decryptJsonObject(encData);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AW", "0", (String) jsonData.get("xfr") + "," + (String) jsonData.get("id") + "," + (String) jsonData.get("device")
					+ ",로그인 요청 전송정보 복호화 후 파기,0 으로 덮어쓰기");

			// Check License
			String spname = (String) jsonData.get("xfr");
			String spip = (String) jsonData.get("spip");

			result = EnvironInform.getInstance().checkLicense(spname);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				jsonData = null;
				return result;
			}

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spname);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						jsonData = null;
						log.error("### smartLogin License IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "IDP smartLogin: License IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					jsonData = null;
					log.error("### smartLogin License IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "IDP smartLogin: License IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// login or connect
			if (jsonData.get("proc").equals("L")) {
				result = authnLoginM(request, jsonData);
			}
			else if (jsonData.get("proc").equals("C")) {
				result = authnConnectM(request, jsonData);
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(7002));
				result.put("message", "IDP smartLogin: Invalid Process");
				result.put("data", "");
			}

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				jsonData = null;
				return result;
			}

			// response
			result = null;
			result = generateResponseM(request, jsonData);

			jsonData = null;
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(7003));
			result.put("message", "IDP smartLogin Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e.toString());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject authnLoginM(HttpServletRequest request, JSONObject jsonData)
	{
		JSONObject result = null;

		try {
			String spName = (String) jsonData.get("xfr");
			String id = (String) jsonData.get("id");
			String pw = (String) jsonData.get("pw");
			String device = (String) jsonData.get("device");
			String appl = (String) jsonData.get("appl");

			request.setAttribute("logintype", "ID_PW");
			request.setAttribute("spname", spName);
			request.setAttribute("id", id);
			request.setAttribute("pw", pw);
			request.setAttribute("device", device);
			request.setAttribute("applcode", appl);
			request.setAttribute("br", "MB");

			// 로그인
			result = null;
			result = UserApiFactory.getUserApi().smartLogin(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}
		}
		catch (Exception e) {
			log.error("### authnLogin() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7004));
			result.put("message", "IDP: authnLoginM() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject authnConnectM(HttpServletRequest request, JSONObject jsonData)
	{
		JSONObject result = null;

		try {
			String userId = (String) jsonData.get("id");
			String authcode = (String) jsonData.get("authcode");
			//String blockid = (String) reqData.get("blockid");

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authcode) == null ? null : (AuthnIssue) authcodeMap.get(authcode);

			if (authnIssue == null) {
				// 다중화 서버 간 동기화
				authnIssue = getAuthnIssueByEvent(authcode);

				if (authnIssue == null) {
					result = new JSONObject();
					result.put("code", String.valueOf(7005));
					result.put("message", "IDP authnConnectM: SSO Token is null");
					result.put("data", "");
					return result;
				}
			}

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			SSOToken mToken = cryptoApi.decryptToken(mapToken, mapTKey);

			if (mToken == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(7006));
				result.put("message", "IDP authnConnectM: SSO Token is null");
				result.put("data", "");
				return result;
			}

			// id check
			if (!userId.equals(mToken.getId())) {
				log.error("### authnConnectM() Mismatch userid: {},{}", userId, mToken.getId());

				result = new JSONObject();
				result.put("code", String.valueOf(7007));
				result.put("message", "IDP authnConnectM: SSO Token is null");
				result.put("data", "");
				return result;
			}

			mToken.finalize();

			// connect log
			String userIp = (String) jsonData.get("device");
			String spName = (String) jsonData.get("xfr");
			String userBr = "MB";

			UserApiFactory.getUserApi().setConnectLog(userId, userIp, userBr, spName);
			Util.setAuditInfo(userId, "AH", "0", userIp + ", " + spName);

			request.setAttribute(CommonProvider.SESSION_AUTHCODE, authcode);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
			return result;
		}
		catch (Throwable e) {
			log.error("### authnConnectM() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7008));
			result.put("message", "IDP: authnConnectM() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}
	}

	public JSONObject generateResponseM(HttpServletRequest request, JSONObject jsonData)
	{
		JSONObject result = null;
		SSOToken mToken = null;

		try {
			String authcode = Util.getAttribute(request, CommonProvider.SESSION_AUTHCODE);

			if (Util.isEmpty(authcode)) {
				result = new JSONObject();
				result.put("code", String.valueOf(7009));
				result.put("message", "IDP generateResponseM: SSO Authcode empty");
				result.put("data", "");
				return result;
			}

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authcode) == null ? null : (AuthnIssue) authcodeMap.get(authcode);

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOCryptoApi cryptoApi = SSOCryptoApi.getInstance();

			mToken = cryptoApi.decryptToken(mapToken, mapTKey);

			if (mToken == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(7010));
				result.put("message", "IDP generateResponseM: SSO Token is null");
				result.put("data", "");
				return result;
			}

			String spName = (String) jsonData.get("xfr");
			String xid = (String) jsonData.get("xid");
			String tid = Util.generateUUID();

			JSONObject sData = new JSONObject();
			sData.put("id", mToken.getId());
			sData.put("authcode", authcode);
			sData.put("token", mToken.getTokenValue().toString());
			sData.put("auid", xid);
			sData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(sData, spName);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encData);

			try { mToken.finalize(); } catch (Throwable e) {}
		}
		catch (Exception e) {
			log.error("### generateResponseM() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7011));
			result.put("message", "IDP: generateResponseM() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject smartLogout(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

			if (Util.isEmpty(encData)) {
				result = new JSONObject();
				result.put("code", String.valueOf(7012));
				result.put("message", "IDP smartS2SLogout: Empty Parameter");
				result.put("data", "");
				return result;
			}

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			// Decrypt Data
			JSONObject jsonData = crypto.decryptJsonObject(encData);

			String id = (String) jsonData.get("id");
			String device = (String) jsonData.get("device");
			String authcode = (String) jsonData.get("authcode");

			Map<String, Object> authcodeMap = SessionManager.getInstance().getAuthcodeMap();
			AuthnIssue authnIssue = authcodeMap.get(authcode) == null ? null : (AuthnIssue) authcodeMap.get(authcode);

			if (authnIssue == null) {
				log.debug("### smartLogout authnIssue null: {}/{}/{}", id, device, authcode);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", "");
				return result;
			}

			if (!id.equals(authnIssue.getUserId())) {
				log.debug("### smartLogout map user: {}/{}/{}/{}", id, device, authcode, authnIssue.getUserId());
			}

			if (!device.equals(authnIssue.getDeviceId())) {
				log.debug("### smartLogout map device: {}/{}/{}/{}", id, device, authcode, authnIssue.getDeviceId());
			}

			String authInfo = authnIssue.getAuthnInfo();
			int idx = authInfo.indexOf(".");
			String mapToken = authInfo.substring(0, idx);
			String mapTKey = authInfo.substring(idx + 1);

			SSOToken mToken = crypto.decryptToken(mapToken, mapTKey);

			if (mToken == null) {
				log.debug("### smartLogout token null: {}/{}/{}", id, device, authcode);
				authcodeMap.remove(authcode);

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", "");
				return result;
			}

			if (!id.equals(mToken.getId())) {
				log.debug("### smartLogout token user: {}/{}/{}/{}", id, device, authcode, mToken.getId());
			}

			setLogoutInfoM(request, jsonData, mToken.getProperty("LOGIN_TYPE"));

			Util.zeroize(authInfo);
			Util.zeroize(mapToken);
			Util.zeroize(mapTKey);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), id, "BD", "0", device);

			authcodeMap.remove(authcode);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");

			try { mToken.finalize(); } catch (Throwable e) {}
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(7013));
			result.put("message", "IDP: smartLogout() Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e.toString());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject csLogout(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

			if (Util.isEmpty(encData)) {
				result = new JSONObject();
				result.put("code", String.valueOf(7021));
				result.put("message", "IDP csLogout: Empty Parameter");
				result.put("data", "");
				return result;
			}

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			String strJson = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(strJson);

			String id = (String) jsonData.get("id");
			String ip = (String) jsonData.get("device");

			if (Util.isEmpty(id)) {
				result = new JSONObject();
				result.put("code", String.valueOf(7022));
				result.put("message", "IDP csLogout: Empty Parameter");
				result.put("data", "");
				return result;
			}

			UserApiFactory.getUserApi().clearCSLoginTime(id, ip);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", "");
		}
		catch (Exception e) {
			result = new JSONObject();
			result.put("code", String.valueOf(7023));
			result.put("message", "IDP: csLogout() Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e.toString());
			e.printStackTrace();
		}

		return result;
	}

	public void setLogoutInfoM(HttpServletRequest request, JSONObject jsonData, String loginType)
	{
		try {
			String br = "MB";

			String id = (String) jsonData.get("id");
			String device = (String) jsonData.get("device");
			String spName = (String) jsonData.get("xfr");

			UserApi userApi = UserApiFactory.getUserApi();

			userApi.clearLoginIP(id, device, br);
			userApi.clearIpInfo(id, device, br);
			userApi.setLogoutLog(id, device, br, loginType, spName);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	// C/S
	public JSONObject csLogin(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### 인증 비활성화 상태");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

			if (Util.isEmpty(encData)) {
				result = new JSONObject();
				result.put("code", String.valueOf(7015));
				result.put("message", "IDP csLogin: Empty parameter");
				result.put("data", "");
				return result;
			}

			// Decrypt Data
			JSONObject jsonData = SSOCryptoApi.getInstance().decryptJsonObject(encData);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AW", "0", (String) jsonData.get("xfr") + "," + (String) jsonData.get("id") + "," + (String) jsonData.get("device")
					+ ",로그인 요청 전송정보 복호화 후 파기,0 으로 덮어쓰기");

			// Check License
			String spname = (String) jsonData.get("xfr");
			String spip = (String) jsonData.get("spip");

			result = EnvironInform.getInstance().checkLicense(spname);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				jsonData = null;
				return result;
			}

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spname);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						jsonData = null;
						log.error("### csLogin License IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "IDP csLogin: License IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					jsonData = null;
					log.error("### csLogin License IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "IDP csLogin: License IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// login
			if (jsonData.get("proc").equals("L")) {
				result = authnLoginC(request, jsonData);
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(7016));
				result.put("message", "IDP csLogin: Invalid Process");
				result.put("data", "");
			}

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				jsonData = null;
				return result;
			}

			// response
			result = null;
			result = generateResponseC(request, jsonData);

			jsonData = null;
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(7017));
			result.put("message", "IDP csLogin Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e.toString());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject authnLoginC(HttpServletRequest request, JSONObject jsonData)
	{
		JSONObject result = null;

		try {
			String spName = (String) jsonData.get("xfr");
			String id = (String) jsonData.get("id");
			String pw = (String) jsonData.get("pw");
			String device = (String) jsonData.get("device");
			String appl = (String) jsonData.get("appl");

			request.setAttribute("logintype", "ID_PW");
			request.setAttribute("spname", spName);
			request.setAttribute("id", id);
			request.setAttribute("pw", pw);
			request.setAttribute("device", device);
			request.setAttribute("applcode", appl);
			request.setAttribute("br", "CS");

			// 로그인
			result = null;
			result = UserApiFactory.getUserApi().smartLogin(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			UserApiFactory.getUserApi().setCSLoginTime(id);
		}
		catch (Exception e) {
			log.error("### authnLogin() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7018));
			result.put("message", "IDP: authnLoginC() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject generateResponseC(HttpServletRequest request, JSONObject jsonData)
	{
		JSONObject result = null;

		try {
			StringBuilder sbToken = request.getAttribute(CommonProvider.SESSION_TOKEN) == null ? null
					: (StringBuilder) request.getAttribute(CommonProvider.SESSION_TOKEN);

			if (sbToken == null) {
				result = new JSONObject();
				result.put("code", String.valueOf(7019));
				result.put("message", "IDP generateResponseC: SSO Token empty");
				result.put("data", "");
				return result;
			}

			SSOToken mToken = new SSOToken(sbToken);

			String spName = (String) jsonData.get("xfr");
			String xid = (String) jsonData.get("xid");
			String tid = Util.generateUUID();

			JSONObject sData = new JSONObject();
			sData.put("id", mToken.getId());
			sData.put("token", mToken.getTokenValue().toString());
			sData.put("auid", xid);
			sData.put("xid", tid);

			String encData = SSOCryptoApi.getInstance().encryptJsonObject(sData, spName);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encData);

			try { mToken.finalize(); } catch (Throwable e) {}
		}
		catch (Exception e) {
			log.error("### generateResponseC() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7020));
			result.put("message", "IDP: generateResponseC() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	// C/S 2FA
	public JSONObject csLogin2FA(HttpServletRequest request)
	{
		JSONObject result = null;

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### 인증 비활성화 상태");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

			if (Util.isEmpty(encData)) {
				result = new JSONObject();
				result.put("code", String.valueOf(7015));
				result.put("message", "IDP csLogin2FA: Empty parameter");
				result.put("data", "");
				return result;
			}

			// Decrypt Data
			JSONObject jsonData = SSOCryptoApi.getInstance().decryptJsonObject(encData);

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
					"AW", "0", (String) jsonData.get("xfr") + "," + (String) jsonData.get("id") + "," + (String) jsonData.get("device")
					+ ",로그인 요청 전송정보 복호화 후 파기,0 으로 덮어쓰기");

			// Check License
			String spname = (String) jsonData.get("xfr");
			String spip = (String) jsonData.get("spip");

			result = EnvironInform.getInstance().checkLicense(spname);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				jsonData = null;
				return result;
			}

			// SP: IP License Check
			HashMap<String, String> licMap = (HashMap<String, String>) SessionManager.getInstance().getLicenseMap();
			String licCheck = licMap.get(spname);

			if (licCheck != null && licCheck.length() > 1) {
				String[] div = spip.split(";");

				log.debug("### SP license IP : {}", licCheck);
				log.debug("### SP request IP : {}", spip);

				if (div.length > 0) {
					boolean check = false;

					for (int i = 0; i < div.length; i++) {
						if (licCheck.indexOf(div[i]) >= 0) {
							check = true;
							break;
						}
					}

					if (!check) {
						jsonData = null;
						log.error("### csLogin License IP Invalid");

						result = new JSONObject();
						result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
						result.put("message", "IDP csLogin2FA: License IP Invalid");
						result.put("data", "");
						return result;
					}
				}
				else {
					jsonData = null;
					log.error("### csLogin License IP Empty");

					result = new JSONObject();
					result.put("code", String.valueOf(MStatus.AUTH_SUBJECT_VALUE_INVALID));
					result.put("message", "IDP csLogin2FA: License IP Empty");
					result.put("data", "");
					return result;
				}
			}

			// login
			if (jsonData.get("proc").equals("L")) {
				result = authnLoginC2FA(request, jsonData);
			}
			else {
				result = new JSONObject();
				result.put("code", String.valueOf(7016));
				result.put("message", "IDP csLogin2FA: Invalid Process");
				result.put("data", "");
			}

			if (!result.get("code").equals(String.valueOf(MStatus.SUCCESS))) {
				jsonData = null;
				return result;
			}

			// response
			result = null;
			result = generateResponseC2FA(request, jsonData);

			jsonData = null;
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(7017));
			result.put("message", "IDP csLogin2FA Exception: " + e.getMessage());
			result.put("data", "");

			log.error(e.toString());
			e.printStackTrace();
		}

		return result;
	}

	public JSONObject authnLoginC2FA(HttpServletRequest request, JSONObject jsonData)
	{
		JSONObject result = null;

		try {
			String spName = (String) jsonData.get("xfr");
			String id = (String) jsonData.get("id");
			String pw = (String) jsonData.get("pw");
			String device = (String) jsonData.get("device");
			String authstep = (String) jsonData.get("authstep");
			String mfatype = (String) jsonData.get("mfatype");
			
			request.setAttribute("logintype", "ID_PW");
			request.setAttribute("spname", spName);
			request.setAttribute("id", id);
			request.setAttribute("pw", pw);
			request.setAttribute("device", device);
			request.setAttribute("br", "CS");
			request.setAttribute("authstep", authstep);
			request.setAttribute("mfatype", mfatype);

			// 로그인
			result = null;
			result = UserApiFactory.getUserApi().smartLogin2FA(request);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				return result;
			}

			if (authstep.equals("2nd")) {
				UserApiFactory.getUserApi().setCSLoginTime(id);
			}
		}
		catch (Exception e) {
			log.error("### authnLoginC2FA() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7018));
			result.put("message", "IDP: authnLoginC2FA() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public JSONObject generateResponseC2FA(HttpServletRequest request, JSONObject jsonData)
	{
		JSONObject result = null;

		try {

			String spName = (String) jsonData.get("xfr");
			String xid = (String) jsonData.get("xid");
			String tid = Util.generateUUID();
			String id = (String) jsonData.get("id");
			String authstep = (String) jsonData.get("authstep");
			String token = "";

			if (authstep.equals("2nd")) {
				StringBuilder sbToken = request.getAttribute(CommonProvider.SESSION_TOKEN) == null ? null
						: (StringBuilder) request.getAttribute(CommonProvider.SESSION_TOKEN);

				if (sbToken == null) {
					result = new JSONObject();
					result.put("code", String.valueOf(7019));
					result.put("message", "IDP generateResponseC2FA: SSO Token empty");
					result.put("data", "");
					return result;
				}

				SSOToken mToken = new SSOToken(sbToken);
				token = mToken.getTokenValue().toString();

				try { mToken.finalize(); } catch (Throwable e) {}
			}

			JSONObject sData = new JSONObject();

			sData.put("id", id);
			sData.put("auid", xid);
			sData.put("xid", tid);
			sData.put("token", token);
			String encData = SSOCryptoApi.getInstance().encryptJsonObject(sData, spName);

			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", encData);
		}
		catch (Exception e) {
			log.error("### generateResponseC2FA() Exception: {}", e.getMessage());

			result = new JSONObject();
			result.put("code", String.valueOf(7020));
			result.put("message", "IDP: generateResponseC2FA() Exception: " + e.getMessage());
			result.put("data", "");
			return result;
		}

		return result;
	}

	public String getProviderNameByUrl(String relayState)
	{
		try {
			MetadataRepository meta = MetadataRepository.getInstance();
			List<String> spNames = meta.getSPNames();

			for (int i = 0; i < spNames.size(); i++) {
				String spName = spNames.get(i);
				SPSSODescriptor spDesc = meta.getSPDescriptor(spName);

				if (checkEndpoint(relayState, spDesc))
					return spName;
			}
		}
		catch (Exception e) {
			log.error("### getProviderNameByUrl: Exception: {}", e.getMessage());
			return null;
		}

		return null;
	}

	private boolean checkEndpoint(String relayState, SPSSODescriptor spDesc)
	{
		String relay = null;

		try {
			relay = URLDecoder.decode(relayState, "UTF-8");
		}
		catch (Exception e) {
			log.error("### checkEndpoint: relayState: {}", relayState);
			log.error("### checkEndpoint: URLDecoder: Exception: {}", e.getMessage());
			relay = relayState;
		}

		int index = relay.indexOf("?");

		if (relay.indexOf("?") >= 0)
			relay = relay.substring(0, index);

		// RelayState URL과 ServiceDiscriptor URL을 비교하여 일치 여부 return
		List<AssertionConsumerService> serviceList = spDesc.getAssertionConsumerServices();

		for (int i = 0; i < serviceList.size(); i++) {
			AssertionConsumerService service = serviceList.get(i);

			if (service.getLocation().indexOf(relay) >= 0)
				return true;
		}

		return false;
	}

	public JSONObject generateProxyConnect(HttpServletRequest request)
	{
		log.debug("### generateProxyConnect");
		JSONObject result = new JSONObject();

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### generateProxyConnect: 인증 비활성화 상태");

				result.put("code", String.valueOf(MStatus.AUTH_NON_ACTIVE));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			String relayState = request.getParameter(PARAM_RELAYSTATE);

			if (Util.isEmpty(relayState)) {
				log.error("### generateProxyConnect: RelayState Empty");

				result.put("code", String.valueOf(MStatus.AUTH_RELAYSTATE_EMPTY));
				result.put("message", "IDP: RelayState Empty");
				result.put("data", "");
				return result;
			}

			String spname = getProviderNameByUrl(relayState);
			
			if (Util.isEmpty(spname)) {
				log.error("### generateProxyConnect: Not Match RelayState");

				result.put("code", String.valueOf(MStatus.AUTH_RELAYSTATE_NOT_MATCH));
				result.put("message", "IDP: Not Match RelayState");
				result.put("data", "");
				return result;
			}

			HttpSession session = request.getSession(false);

			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String tokenDEK = (String) session.getAttribute(SESSION_TOKEN_EK);
			String authcode = (String) session.getAttribute(SESSION_AUTHCODE);

			if (Util.isEmpty(encToken) || Util.isEmpty(tokenDEK) || Util.isEmpty(authcode)) {
				log.error("### generateProxyConnect: SSO Not Login");

				result.put("code", String.valueOf(MStatus.AUTH_NOT_LOGIN));
				result.put("message", "IDP: SSO Not Login");
				result.put("data", "");
				return result;
			}

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			SSOToken token = null;

			try {
				token = crypto.decryptToken(encToken, tokenDEK);
			}
			catch (Exception e) {
				token = null;
			}

			if (token == null) {
				log.error("### generateProxyConnect: SSO Token Null");

				result.put("code", String.valueOf(MStatus.AUTH_TOKEN_NULL));
				result.put("message", "IDP: SSO Token Null");
				result.put("data", "");
				return result;
			}

			String ip = Util.getClientIP(request);
			String challenge = new String(Hex.encode(crypto.createRandom(16).getBytes()));
			String timestamp = new DecimalFormat("000000000000000").format(System.currentTimeMillis());

			JSONObject retJson = new JSONObject();
			retJson.put("device", ip);
			retJson.put("auth", authcode);
			retJson.put("sp", spname);
			retJson.put("chlg", challenge);
			retJson.put("time", timestamp);

			byte[] sendByte = crypto.encryptSym(retJson.toJSONString().getBytes());
			String sendData = SSOCryptoApi.encode64(sendByte);

			session.setAttribute("PXCHLG", challenge);

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", sendData);
		}
		catch (Exception e) {
			log.error("### generateProxyConnect: Exception: {}", e.getMessage());

			result.put("code", String.valueOf(7020));
			result.put("message", "IDP: generateProxyConnect: Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public JSONObject authnProxyConnect(HttpServletRequest request)
	{
		log.debug("### authnProxyConnect");
		JSONObject result = null;

		try {
			SSOConfig config = SSOConfig.getInstance();

			if (config.getAuthStatus() != 0) {
				log.error("### authnProxyConnect: 인증 비활성화 상태");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "인증 비활성화 상태");
				result.put("data", "");
				return result;
			}

			String encData = Util.getCookieValue(request, "AI");

			if (Util.isEmpty(encData)) {
				log.error("### authnProxyConnect: Authn Packet Empty");

				result = new JSONObject();
				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Authn Packet Empty");
				result.put("data", "");
				return result;
			}

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(URLDecoder.decode(encData, "UTF-8")));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String _ip = (String) jsonData.get("device");
			String _authcode = (String) jsonData.get("auth");
			String _spname = (String) jsonData.get("sp");
			String _challenge = (String) jsonData.get("chlg");
			String _timestamp = (String) jsonData.get("time");

			if (Util.isEmpty(_ip) || Util.isEmpty(_authcode) || Util.isEmpty(_challenge)
					|| Util.isEmpty(_timestamp) || Util.isEmpty(_spname)) {
				log.error("### authnProxyConnect: Authn Info Empty");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Authn Info Empty");
				result.put("data", "");
				return result;
			}

			// License Check
			result = EnvironInform.getInstance().checkLicense(_spname);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### authnProxyConnect: {}", result.get("message"));

				result.put("code", String.valueOf(MStatus.FAIL));
				return result;
			}

			String ip = (String) request.getHeader(config.getString("proxy.clientip", "X-Real-IP"));

			if (Util.isEmpty(ip)) {
				log.error("### authnProxyConnect: Client IP Empty");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Client IP Empty");
				result.put("data", "");
				return result;
			}

			if (!ip.equals(_ip)) {
				log.error("### authnProxyConnect: Not Match Client IP");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Not Match Client IP");
				result.put("data", "");
				return result;
			}

			HttpSession session = request.getSession(false);
			String challenge = (String) session.getAttribute("PXCHLG");
			session.removeAttribute("PXCHLG");

			if (Util.isEmpty(challenge)) {
				log.error("### authnProxyConnect: Challenge Empty");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Challenge Empty");
				result.put("data", "");
				return result;
			}

			if (!challenge.equals(_challenge)) {
				log.error("### authnProxyConnect: Not Match Challenge");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Not Match Challenge");
				result.put("data", "");
				return result;
			}

			long reqTime = Long.parseLong(_timestamp) + (config.getInt("proxy.timeout", 3) * 1000);  // 3 sec
			long curTime = System.currentTimeMillis();

			if (curTime > reqTime) {
				log.error("### authnProxyConnect: Timeout Packet");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Timeout Packet");
				result.put("data", "");
				return result;
			}

			String authcode = (String) session.getAttribute(SESSION_AUTHCODE);
			String encToken = (String) session.getAttribute(SESSION_TOKEN);
			String tokenDEK = (String) session.getAttribute(SESSION_TOKEN_EK);

			if (Util.isEmpty(authcode) || Util.isEmpty(encToken) || Util.isEmpty(tokenDEK)) {
				log.error("### authnProxyConnect: SSO Not Login");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: SSO Not Login");
				result.put("data", "");
				return result;
			}

			if (!authcode.equals(_authcode)) {
				log.error("### authnProxyConnect: Not Match Authcode");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: Not Match Authcode");
				result.put("data", "");
				return result;
			}

			SSOToken token = null;

			try {
				token = crypto.decryptToken(encToken, tokenDEK);
			}
			catch (Exception e) {
				token = null;
			}

			if (token == null) {
				log.error("### authnProxyConnect: SSO Token Null");

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "IDP: authnProxyConnect: SSO Token Null");
				result.put("data", "");
				return result;
			}

			String sendData = SSOCryptoApi.encode64(token.toJsonString().getBytes());

			try { token.finalize(); } catch (Throwable e) {}

			// connect log
			String userId = (String) session.getAttribute("SSO_ID");
			String userBr = request.getAttribute("loginBr") == null ? "NN" : (String) request.getAttribute("loginBr");

			UserApiFactory.getUserApi().setConnectLog(userId, _ip, userBr, _spname);
			Util.setAuditInfo(userId, "AH", "0", _ip + ", " + _spname);

			result.put("code", String.valueOf(MStatus.SUCCESS));
			result.put("message", "SUCCESS");
			result.put("data", sendData);
		}
		catch (Exception e) {
			log.error("### authnProxyConnect: Exception: {}", e.getMessage());

			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(MStatus.FAIL));
			result.put("message", "IDP: authnProxyConnect: Exception: " + e.getMessage());
			result.put("data", "");
		}

		return result;
	}

	public RootAuthSession getRootAuthSessionByEvent(String rootAuthSessionId)
	{
		SyncMonitor.startMonitor();
		SyncMonitor.requestRootAuthSessionEvent(rootAuthSessionId);

		int waitCount = 3;

		while (waitCount != 0) {
			try {
				Thread.sleep(200);
			}
			catch (InterruptedException e) {
				e.printStackTrace();
				return null;
			}

			RootAuthSession rootAuthSession = OidcSessionManager.getInstance().getRootAuthSession(rootAuthSessionId);

			if (rootAuthSession == null) {
				waitCount--;
				continue;
			}
			else {
				return rootAuthSession;
			}
		}

		return null;
	}

}