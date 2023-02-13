<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%
	String DEFAULT_SSO_PATH = "/sso";

	// 로그인 페이지
	String LOGIN_PAGE = DEFAULT_SSO_PATH + "/admin/adminLogin.jsp";

	// 로그아웃 페이지
	String LOGOUT_PAGE = DEFAULT_SSO_PATH + "/admin/adminLogout.jsp";

	// Admin 종료 후 리턴 페이지
	String BASE_PAGE = DEFAULT_SSO_PATH + "/admin/adminLogin.jsp";

	// Admin 메인 페이지
	String ADMIN_MAIN_PAGE = DEFAULT_SSO_PATH + "/admin/main.jsp";

	String LOGIN_ERROR_PAGE = DEFAULT_SSO_PATH + "/admin/error.jsp";

	String DEFAULT_SET_PATH = "/WEB-INF/classes";
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
<script type="text/javascript">
	function XSSCheck(strVal)
	{     
		if (strVal != null && strVal.length > 0) {
			strVal = strVal.replace(/\</g, "&lt;");
			strVal = strVal.replace(/\>/g, "&gt;");
			strVal = strVal.replace(/\&/g, "&amp;");
			strVal = strVal.replace(/\"/g, "&quot;");
			strVal = strVal.replace(/\'/g, "&apos;");
		}

		return strVal;
	}

	function ajaxerror(x, status, error)
	{
		if (x.status == 0) {
			alert(" 오프라인 상태 입니다.");
			parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
		}
		else if (x.status == 404) {
			alert(" 페이지를 찾을 수 없습니다.");
		}
		else if (x.status == 500) {
			alert(" 서버 에러 입니다.");
		}
		else if (x.status == 12029) {
			alert(" 서버에 연결할 수 없습니다.");
		}
		else if (status == "parsererror") {
			var errcheck = x.responseText.indexOf("Error :");
			if (errcheck != null && errcheck == 0) {
				alert($.trim(x.responseText).substr(7));
				return;
			} else {
				alert(" 사용자 세션이 만료되어,\n\n 로그인 페이지로 이동합니다.");
				parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				return;
			}
		}
		else {
			alert("Error : " + x.status + "\n\n" + $.trim(x.responseText));
		}
	}
</script>