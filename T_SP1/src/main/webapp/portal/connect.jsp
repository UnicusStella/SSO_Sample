<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="/sso/common.jsp"%>

<!DOCTYPE html>
<html lang="ko">
<head>
	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>

	<script src="./js/jquery-3.4.1.min.js" type="text/javascript"></script>
	<script src="/sso/js/magicsso.js" type="text/javascript"></script>
	<link href="./css/sso-common.css?v=2" rel="stylesheet" type="text/css"/>
	<link href="./css/sso-connect.css?v=2" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<div class="page-breadcrumb">
			HOME / SSO Agent / SSO 연계
		</div>
		<div class="page-header">
			<h4 class="title">SSO 연계</h4>
		</div>
		<div class="content_box">
			<input class="input_url mb-10" type="text" id="in_url" placeholder="연계 URL"/>
			<button class="btn" type="button" id="btn_connect">연 계</button>
		</div>
	</div>

<script type="text/javascript">
	$(document).ready(function(){
		$('#in_url').val("http://sp2.dev.com:40007/sso/RequestConnect.jsp?RelayState=/portal/connectMain.jsp");
		//$('#in_url').val("http://idp.dev.com:40001/sso/proxyConnect.jsp?RelayState=http://proxy.dev.com/connect/setProxyAuth.jsp");
	});

	$("#btn_connect").click(function() {
		if (MagicSSO.isLogon()) {
			window.open($('#in_url').val(), "_blank");
		}
		else {
			location.href = "<%=XSSCheck(DEFAULT_BASE_URL)%>";
		}
	});
</script>
</body>
</html>