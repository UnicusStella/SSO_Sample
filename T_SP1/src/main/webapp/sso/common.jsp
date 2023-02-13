<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"
%><%@ page import="com.dreamsecurity.sso.agent.util.Util"
%><%
	// SSO path
	String DEFAULT_SSO_PATH = "/sso";

	// home path name (Fix)
	String DEFAULT_SET_NAME = "dreamsecurity.saml.path";

	// home path 기본위치 (Fix)
	String DEFAULT_SET_PATH = "/WEB-INF/dreamsso";

	////////////////////////////////////////////////////////////////////////////
	// home return URL
	String HOME_RETURN_URL = Util.getURL(request, DEFAULT_SSO_PATH + "/inc/sessionView.jsp");

	// 로그인 후 이동할 URL
	String DEFAULT_RELAYSTATE = "/portal/main.jsp";
	//String DEFAULT_RELAYSTATE = DEFAULT_SSO_PATH + "/inc/sessionView.jsp";

	// EAM 권한 가져올 URL
	String GET_ROLE_URL = "http://iam.dev.com:50002/api/role";
	
	// EAM 권한 가져오고 return할 URL
	String HOME_RETURN_ROLE_URL = "http://sp1.dev.com:40004/sso/ResponseRole.jsp";

	// EAM 권한 관련 오류 MESSAGE
	String ERROR_ROLE_MESSAGE = "권한 조회 실패";

	// 비밀번호 초기화를 위해 인증서 로그인 후 이동 페이지
	String PW_INIT_RELAYSTATE = DEFAULT_SSO_PATH + "/PwReset.jsp";

	// 에러 페이지
	String ERROR_PAGE = "/error.jsp";

	// Base URL (주로 로그인 페이지 URL 세팅)
	String DEFAULT_BASE_URL = "http://sp1.dev.com:40004/portal/loginSample.jsp";

	// 로그아웃 후 이동할 URL (DEFAULT_BASE_URL과 다른 URL이면 세팅)
	String PAGE_URL_AFTER_LOGOUT = DEFAULT_BASE_URL;

	// 연계 실패시 리턴 URL 이름 (Fix)
	//String TEMPLETE_PARAM_FAILRTNURL = "FailRtnUrl";

	// WEB -> CS 연계 URL
	String CS_CONNECT_URL = Util.getURL(request, DEFAULT_SSO_PATH + "/CreateRequestCS.jsp");

	// RelayState 허용 URL
	String allowURL[] = {
		request.getScheme() + "://" + request.getServerName(),
		Util.getURL(request, "/portal/main.jsp"),
		Util.getURL(request, "/portal/connectMain.jsp"),
		Util.getURL(request, DEFAULT_SSO_PATH + "/inc/sessionView.jsp")
	};

	String LOGOUT_URL = DEFAULT_SSO_PATH + "/Logout.jsp";

	String IDP_CHECK_URL = "http://idp.dev.com:40001/sso/monitor.jsp";

	////////////////////////////////////////////////////////////////////////////
	// ID 입력창 이름
	String PARAM_LOGIN_ID = "loginId";

	// PW 입력창 이름
	String PARAM_LOGIN_PW = "loginPw";

	String PARAM_LOGIN_CH = "loginCh";

	// RelayState 이름 (Fix)
	String PARAM_RELAYSTATE = "RelayState";

	// 서버 세션: SSO 정보
	String SESSION_SSO_ID = "SSO_ID";
	String SESSION_SSO_TOKEN = "_TOKEN";

	String SESSION_ROLE = "_ROLE";

	String FLAG = "^@^";

%><%!
	public String XSSCheck(String value)
	{
		if (value != null && value.trim().length() > 0) {
			value = value.trim();
			value = value.replaceAll("<", "&lt;");
			value = value.replaceAll(">", "&gt;");
			value = value.replaceAll("&", "&amp;");
			value = value.replaceAll("\"", "&quot;");
			value = value.replaceAll("\'", "&apos;");
		}

		return value;
	}
%>