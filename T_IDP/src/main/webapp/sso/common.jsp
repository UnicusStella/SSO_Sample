<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
	// Root path
	String DEFAULT_SSO_PATH = "/sso";

	// RelayState 이름 (Fix)
	String TEMPLETE_PARAM_RELAYSTATE = "RelayState";

	// 관리자 메인 화면 URL (Fix)
	String ADMIN_MAIN_PAGE = DEFAULT_SSO_PATH + "/admin/main.jsp";

	// 연계 실패시 리턴 URL (Fix)
	String TEMPLETE_PARAM_FAILRTNURL = "FailRtnUrl";

	// 인증 성공후 응답처리 URL (Fix)
	String RESPONSE_FORWARD_PAGE = "ResponseForward.jsp";

	// 에러 페이지 URL (Fix)
	String ERROR_PAGE = "/error.jsp";

	// home path 이름 (Fix)
	String DEFAULT_SET_NAME = "dreamsecurity.saml.path";

	// home path 기본위치 (Fix)
	String DEFAULT_SET_PATH = "/WEB-INF/classes";

	// Base URL (주로 로그인 페이지 URL 세팅)
	String DEFAULT_BASE_URL = "http://sp1.dev.com:40004/portal/loginSample.jsp";

	// 서버 로그인 URL
	String SERVER_LOGIN_PAGE = "/Login.jsp";

	String PARAM_LOGIN_ID = "loginId";
	String PARAM_LOGIN_PW = "loginPw";
%>
<%!
	public String getBrowserType(HttpServletRequest request)
	{
		String browser = "";
		String userAgent = request.getHeader("User-Agent").toLowerCase();
		if (userAgent.indexOf("trident") >= 0 || userAgent.indexOf("msie") >= 0) {
			browser = "IE";
		}
		else if (userAgent.indexOf("edg") >= 0) {
			browser = "EG";
		}
		else if (userAgent.indexOf("opr") >= 0 || userAgent.indexOf("opera") >= 0) {
			browser = "OP";
		}
		else if (userAgent.indexOf("chrome") >= 0) {
			browser = "CR";
		}
		else if (userAgent.indexOf("safari") >= 0) {
			browser = "SF";
		}
		else if (userAgent.indexOf("firefox") >= 0) {
			browser = "FF";
		}
		else {
			browser = "NN";
		}
		return browser;
	}

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