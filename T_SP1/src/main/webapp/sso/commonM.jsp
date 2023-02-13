<%
	String DEFAULT_SSO_PATH = "/sso";
	String DEFAULT_SET_PATH = "/WEB-INF/dreamsso";

	String IDP_SERVER = "http://192.168.0.12:40001";
	String SP_SERVER = "http://192.168.0.12:40004";

	// C/S
	String IDP_REQUEST_C_URL = IDP_SERVER + "/sso/RequestC.jsp";

	// Mobile
	String IDP_REQUEST_M_URL = IDP_SERVER + "/sso/RequestM.jsp";
	String IDP_LOGOUT_M_URL = IDP_SERVER + "/sso/LogoutM.jsp";

	// App2Web
	String IDP_REQUEST_URL = IDP_SERVER + "/sso/RequestS.jsp";
	String SP_RESPONSE_URL = SP_SERVER + DEFAULT_SSO_PATH + "/ResponseS.jsp";

	String RELAY_STATE = SP_SERVER + DEFAULT_SSO_PATH + "/inc/sessionView.jsp";
	String DEFAULT_BASE_URL = SP_SERVER + DEFAULT_SSO_PATH + "/inc/sessionView.jsp";
	String ERROR_URL = SP_SERVER + DEFAULT_SSO_PATH + "/errorS.jsp";
%>