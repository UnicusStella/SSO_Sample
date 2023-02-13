<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.net.URLEncoder"%>
<%@ page import="java.util.Iterator"%>
<%@ page import="java.util.Map"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ page import="com.dreamsecurity.sso.agent.util.SAMLUtil"%>
<!-- MagicLine Class -->
<%@ page import="java.math.BigInteger"%>
<%@ page import="java.net.URLDecoder"%>
<%@ page import="com.dreamsecurity.jcaos.x509.X509Certificate"%>
<%@ page import="com.dreamsecurity.jcaos.x509.X509GeneralName"%>
<%@ page import="com.dreamsecurity.jcaos.x509.X509OtherName"%>
<%@ page import="com.dreamsecurity.jcaos.util.encoders.Base64"%>
<%@ page import="com.dreamsecurity.jcaos.util.encoders.Hex"%>
<%@ page import="com.dreamsecurity.jcaos.vid.VID"%>
<%@ page import="com.dreamsecurity.JCAOSProvider"%>
<%@ page import="com.dreamsecurity.magicline.JCaosCheckCert"%>
<!-- MagicLine Class -->
<%@ include file="./common.jsp"%>
<%
	out.clear();
	out = pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	String baseURL = Util.getBaseURL(request);
	String errorURL = baseURL + DEFAULT_SSO_PATH + ERROR_PAGE;

	ServiceProvider sp = null;
	JSONObject result = null;

	try {
		sp = ServiceProvider.getInstance();
	}
	catch (SSOException e) {
		Util.sendErrorURL(response, errorURL, String.valueOf(e.getErrorCode()), e.getMessage());
		return;
	}

	// MagicLine Source Start
	// 서명 검증 셈플
	// 클라이언트에서 받은 서명 데이타를 검증
	String sResult = "";
	String sSignData = null;
	String vidRandom = null;
	JCaosCheckCert jcaosCheck = null;
	//String sIDN = null;
	String sSourceText = null;
	String textCheck = "";
	String sPolicy = "";
	String sidentifyData = "";
	
	// 서명 데이타를  가져옴 
	// 본 셈플에서는 서명 값을 Post Data 의 SignData 에 넣어서 보낸다고 간주 코딩 한다
	sSignData = request.getParameter("signedData");
	sSignData = URLDecoder.decode(sSignData, "utf-8");
	vidRandom = request.getParameter("vidRandom");
	vidRandom = URLDecoder.decode(vidRandom, "utf-8");
	String idn = request.getParameter("idn");
	
	sResult = sResult+"- SignData ["+sSignData+"]<br>\n"+"- VIDData ["+vidRandom+"]<br>\n";

	//System.out.println(sResult);

	// 서명 데이타가 있을때 서명 검증
	if (sSignData != null && sSignData.length() > 0){
		try{
			// API 초기화 (한번만 실행)
			JCAOSProvider.installProvider(false);	
			// 라이센스 경로 설정
			//com.dreamsecurity.jcaos.Environment.setLicensePath("C:/Tomcat 5.5/webapps/MagicLine4/WEB-INF/lib");

			jcaosCheck = new JCaosCheckCert();
			
			// 서버가 알고 잇는 주민등록 번호를 등록한다 
			jcaosCheck.setVIDRandom(idn, vidRandom);
			
			sResult = sResult+"<br>\n- 인증서 검증 시작<br>\n";
			
			// 서명 검증
			// 검증후 원문이 리턴됨
			int iResult = jcaosCheck.checkCert(sSignData);
			/*
			- JCaosCheckCert.checkCert 의 에러코드는 하기와 같습니다.
			JCaosCheckCert.STAT_OK										// 성공
			JCaosCheckCert.STAT_ERR_WRONGCERT							// 정상적인 인증서가 아님
			JCaosCheckCert.STAT_ERR_ETC									// 기타 오류
			JCaosCheckCert.STAT_ERR_VerifyException 					// 서명 검증 실패
			JCaosCheckCert.STAT_ERR_CertificateNotYetValidException 	// 인증서 유효기간 검증 오류
			JCaosCheckCert.STAT_ERR_CertificateExpiredException 		// 인증서 만료
	 		JCaosCheckCert.STAT_ERR_ObtainCertPathException				// 인증서 경로 구축 실패
			JCaosCheckCert.STAT_ERR_BuildCertPathException 				// 인증서 경로 구축 실패
			JCaosCheckCert.STAT_ERR_TrustRootException 					// 신뢰할수 없는 최상위 인증서
			JCaosCheckCert.STAT_ERR_ValidateCertPathException			// 인증서 경로 검증 실패
			JCaosCheckCert.STAT_ERR_RevokedCertException				// 폐지된 인증서
			JCaosCheckCert.STAT_ERR_RevocationCheckException			// CRL 검증 실패
			JCaosCheckCert.STAT_ERR_NotExistSignerCertException			// 서명자 인증서 누락
			JCaosCheckCert.STAT_ERR_IOException							// IOException
			JCaosCheckCert.STAT_ERR_FileNotFoundException				// FileNotFoundException
			JCaosCheckCert.STAT_ERR_NoSuchAlgorithmException			// NoSuchAlgorithmException
			JCaosCheckCert.STAT_ERR_NoSuchProviderException 			// NoSuchProviderException 
			JCaosCheckCert.STAT_ERR_ParsingException        			// ParsingException        
			JCaosCheckCert.STAT_ERR_IdentifyException       			// 본인확인 실패
			*/
			
			if( iResult == 0 ){
				sResult = sResult+ "- 인증서 검증 성공<br>\n";
			}else if( iResult == 3000 ){
				sResult = sResult+ "- 인증서 검증 하지않음<br>\n";
			}else if (  iResult != 0 ){
				// 오류 발생시 오류를 구분
				String sCertResult = null;
				switch(iResult){
					case JCaosCheckCert.STAT_ERR_WRONGCERT							:	// 정상적인 인증서가 아님
						sCertResult = "서명에 사용된 인증서가 정상적인 인증서가 아닙니다.";
						break;
					case JCaosCheckCert.STAT_ERR_RevocationCheckException			:	// CRL 검증 실패
					case JCaosCheckCert.STAT_ERR_NotExistSignerCertException		:	// 서명자 인증서 누락
					case JCaosCheckCert.STAT_ERR_IOException						:	// IOException
					case JCaosCheckCert.STAT_ERR_FileNotFoundException				:	// FileNotFoundException
					case JCaosCheckCert.STAT_ERR_ETC								:	// 기타 오류
					case JCaosCheckCert.STAT_ERR_BuildCertPathException 			:	// 인증서 경로 구축 실패
					case JCaosCheckCert.STAT_ERR_ObtainCertPathException			:	// 인증서 경로 구축 실패
					case JCaosCheckCert.STAT_ERR_ValidateCertPathException			:	// 인증서 경로 검증 실패
					case JCaosCheckCert.STAT_ERR_TrustRootException 				:	// 신뢰할수 없는 최상위 인증서
						sCertResult = "서명 인증서 검증 오류 ["+iResult+"].";
						break;
					case JCaosCheckCert.STAT_ERR_VerifyException 					:	// 서명 검증 실패
						sCertResult = "서명 검증 실패";
						break;
					case JCaosCheckCert.STAT_ERR_CertificateNotYetValidException	: 	// 인증서 유효기간 검증 오류
						sCertResult = "서명 인증서 유효기간 검증 오류";
						break;
					case JCaosCheckCert.STAT_ERR_CertificateExpiredException 		:	// 인증서 만료
						sCertResult = "만료된 인증서 ";
						break;
					case JCaosCheckCert.STAT_ERR_RevokedCertException				:	// 폐지된 인증서
						sCertResult = "폐지된 인증서";
						break;
					default:
						sCertResult = "기타오류 ["+iResult+"]";
						break;
				}
				sResult = "<br>\n- "+sCertResult+" \n[" + jcaosCheck.getLastErr() +"]<br>\n\n"; 
			}
			if( iResult == 0 || iResult == 3000 ){
								
				// 서명에 사용된 인증서를 가져온다
				X509Certificate cert = jcaosCheck.getUserCert();
				String signerDN = cert.getSubjectDN().getName();	// 인증서 DN
				BigInteger serialNumber = cert.getSerialNumber();	// 인증서 시리얼
				
				//System.out.println("#### SignData: " + sSignData);
				
				// 본인확인 
				switch (jcaosCheck.getVIDCheck()){
					case JCaosCheckCert.STAT_VID_NOTCHECK:
						sResult = sResult+"- 본인 확인 하지 않음<br>\n";
						break;
					case JCaosCheckCert.STAT_VID_CHECK_OK:
						sResult = sResult+"- 본인 확인 성공<br>\n";
						break;
					case JCaosCheckCert.STAT_VID_CHECK_FAIL:
						sResult = sResult+"- 본인 확인 실패<br>\n";
						break;
				}
				
				// 화면 출력값 생성
				//sResult = sResult+  "<br>\n- 사용자 DN ["+signerDN+"]<br>\n"+"<br>\n";
				//sResult = sResult+  "- 발급자 DN ["+cert.getIssuerDN().getName()+"]<br>\n"+"<br>\n";
				//sResult = sResult+  "- 인증서 SN ["+cert.getSerialNumber().toString(16)+"]<br>\n"+"<br>\n";
				//sResult = sResult+  "- 인증서 정책 ["+cert.getCertificatePolicies().getPolicyIdentifier(0)+"]<br>\n"+"<br>\n";
			}
		}catch(Exception e){
			// 인증서 검증중 오류가 난 경우
			// 처리를 편하게 하기 위해
			// 상용중에는 사용자의 인증서의 유효성의 문제가 잇는 경우가 대부분 입니다.
			//e.printStackTrace();
			sResult = "서명 검증에 실패 하였습니다.\n [" + e.getMessage()+"]\");";
		}
	} else
	{
		sResult=" - 서명 데이타가 존재하지 않습니다..<br>\n";
	}

	//System.out.println(sResult);
	// MagicLine Source End

	// multi-IdP
	String idp = request.getParameter("idp") == null ? "" : (String) request.getParameter("idp");

	result = sp.generateAuthnRequestCert(request, sSignData, idp);

	if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
		Util.sendErrorURL(response, errorURL, (String) result.get("code"), (String) result.get("message"));
		return;
	}

	if (result.get("data") == null) {
		Util.sendErrorURL(response, errorURL, String.valueOf(MStatus.FAIL), "Generate AuthnRequest Failure.");
		return;
	}

	// create RelayState start
	String relayState = request.getParameter(PARAM_RELAYSTATE);
	if (Util.isEmpty(relayState)) {
		relayState = DEFAULT_RELAYSTATE;
	}

	relayState = Util.getURL(request, relayState);

	StringBuffer addParam = new StringBuffer();
	Map<?,?> parameterMap = request.getParameterMap();
	Iterator<?> iterator = parameterMap.keySet().iterator();
	while (iterator.hasNext()) {
		String name = (String) iterator.next();
		if (name.equals(PARAM_RELAYSTATE) || name.equals(PARAM_LOGIN_CH)
				|| name.equals(PARAM_LOGIN_ID) || name.equals(PARAM_LOGIN_PW)
				|| name.equals("vidRandom") || name.equals("vidType")
				|| name.equals("signData") || name.equals("signedData")) {
			continue;
		}

		if (addParam.length() > 0) {
			addParam.append("&");
		}

		addParam.append(name).append("=").append(request.getParameter(name));
	}

	if (!Util.isEmpty(addParam.toString())) {
		int index = relayState.indexOf("?");
		if (index == -1) {
			relayState = relayState + "?" + addParam.toString();
		}
		else {
			relayState = relayState + "&" + addParam.toString();
		}
	}

	relayState = URLEncoder.encode(relayState, "UTF-8");
	// create RelayState end

 	boolean sendResult = SAMLUtil.sendAuthnRequest(response, (AuthnRequest) result.get("data"), "auth", relayState);
 	if (!sendResult) {
		session.removeAttribute("LGCHLG");
		Util.sendErrorURL(response, errorURL, String.valueOf(MStatus.AUTH_REQ_SEND), "Send AuthnRequest Failure.");
 	}
%>