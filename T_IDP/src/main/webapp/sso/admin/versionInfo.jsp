<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
<script type="text/javascript">
	if ("<%=XSSCheck(adminid)%>" == "") { top.location.href = "<%=XSSCheck(LOGIN_PAGE)%>"; }
</script>

<!DOCTYPE html>
<html lang="ko">
<head>
	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>

	<script src="js/jquery-3.4.1.min.js" type="text/javascript"></script>

	<script src="js/sso-common.js" type="text/javascript"></script>
	<link href="./css/sso-common.css" rel="stylesheet" type="text/css"/>
	<link href="./css/sso-versioninfo.css?v=2" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>

		<div class="page-breadcrumb">
			HOME / 관리자 / 제품 버전 정보
		</div>
		<div class="page-header">
			<h4 class="title">제품 버전 정보</h4>
		</div>

		<div class="content-box width-50p">
			<div class="content-body pt-20 pb-20">
				<table id="info">
					<colgroup>
						<col width="30%">
						<col width="70%">
					</colgroup>
					<tr>
						<td id="colnm">제품명</td>
						<td id="coldata">&nbsp;<%=XSSCheck(SSOConfig.getTOE())%></td>
					</tr>
					<tr>
						<td id="colnm">버전</td>
						<td id="coldata">&nbsp;<%=XSSCheck(SSOConfig.getDetailVersion())%></td>
					</tr>
					<tr>
						<td class="tdlast" id="colnm">구성요소</td>
						<td class="tdlast" id="coldata">&nbsp;<%=XSSCheck(SSOConfig.getElementVersion())%></td>
					</tr>
				</table>
			</div>
		</div>
	</div>

<script type="text/javascript">
	$(document).ready(function(){
		checkAdmin();
	});

	function keydown(event)
	{
		parent.idleTime = new Date(); 

		// Refresh Key Check
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 116 || (event.ctrlKey && keyID == 82)) {  // 116=F5 82=Ctrl+r
			parent.f5key = true;
		}
	}
	$(document).on("keydown", keydown);

	function click()
	{
		parent.idleTime = new Date();
	}
	$(document).on("click", click);

</script>
</body>
</html>