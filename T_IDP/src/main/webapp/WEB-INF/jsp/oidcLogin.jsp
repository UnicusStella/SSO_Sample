<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%@ page import="com.dreamsecurity.sso.server.util.OIDCUtil"%>
<%@ include file="/WEB-INF/jsp/common.jsp"%>
<%
	String subAuthSessionId = request.getAttribute("SubAuthSessionId") == null ? "" : (String) request.getAttribute("SubAuthSessionId");
	String errorMessage = request.getAttribute("ErrorMessage") == null ? "" : (String) request.getAttribute("ErrorMessage");
	String baseUrl = OIDCUtil.generateBaseUrl(request);
	String target = SSOConfig.getInstance().getString("oidc.endpoint.authenticate", "/oidc/authenticate");
%>
<!DOCTYPE html>
<html lang="ko">
<head>
<title>Magic SSO - Login</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" type="text/css" href="/sso/css/dream_sso.css">
<script type="text/javascript">
document.onkeypress = getKey;

document.addEventListener("DOMContentLoaded", function(){
	document.getElementById("uid").focus();
});

var errorMessage = "<%=XSSCheck(errorMessage)%>";
if (errorMessage != "")
	alert(errorMessage);

var target = "<%=XSSCheck(target)%>";
if (target == "")
	alert(" 비정상 로그인 페이지입니다.(2)");

function getKey(keyStroke)
{
	if (window.event.keyCode == 13)
		loginStart();
}

function loginStart()
{
	var frm = document.getElementById("loginForm");

	if (frm.SubAuthSessionId.value == "") {
		alert(" 비정상 로그인 페이지입니다.(1)");
		return;
	}

	if (frm.uid.value == "" || frm.upw.value == "") {
		alert(" 아이디 또는 비밀번호를 입력해 주세요.");
		return;
	}

	frm.action = "<%=XSSCheck(target)%>";
	frm.submit();
}
</script>
</head>
<body>
<form name="loginForm" id="loginForm" method="post">
<input type="hidden" id="SubAuthSessionId" name="SubAuthSessionId" value="<%=XSSCheck(subAuthSessionId)%>"/>
<div class="wrap">
    <div class="con_wrap">
        <div class="contents_box">
            <div class="login_area">
                <div class="login_box">
                    <div class="login_tit">
                        <img src="/sso/images/login_logo.png" alt="Magic SSO"><br/><span>로그인</span>
                    </div>
                    <div class="input_wrap">
                        <input type="text" class="input_box width_80p mb_10" name="uid" id="uid" placeholder="ID" tabindex=1 maxlength="50" autocomplete="off"/>
                        <input type="password" class="input_box width_80p mb_20" name="upw" id="upw" placeholder="PW" tabindex=2 maxlength="50"/>
                        <button type="button" class="blue_btn width_80p" onclick="loginStart(); return false;"><span>로그인</span></button>
                    </div>
                </div>
            </div>
            <div class="contact_noti">
                <span>Copyright ⓒ Dreamsecurity Co.,Ltd. All rights reserved.</span>
            </div>
        </div>
    </div>
</div>
</form>
</body>
</html>