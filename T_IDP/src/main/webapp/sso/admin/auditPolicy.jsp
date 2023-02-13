<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ page import="com.dreamsecurity.sso.server.api.admin.AdminController"%>
<%@ include file="adminCommon.jsp"%>
<%@ include file="sub/checkAdmin.jsp"%>
<%
	AdminController adminApi = new AdminController();
	String challenge = adminApi.createAdminCSRFToken(request);
%>
<script type="text/javascript">
	if ("<%=XSSCheck(adminid)%>" == "") { top.location.href = "<%=XSSCheck(LOGIN_PAGE)%>"; }
	if ("<%=XSSCheck(admintype)%>" != "S") { top.location.href = "<%=XSSCheck(LOGOUT_PAGE)%>"; }
</script>

<!DOCTYPE html>
<html lang="ko">
<head>
	<meta charset="utf-8"/>
	<meta http-equiv="Content-Style-Type" content="text/css"/>
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>

	<!--jgGrid, jsTree Tags-->
	<link href="css/jquery-ui.css" type="text/css" rel="stylesheet"/>
	<link href="css/jquery-ui-1.8.21.custom.css" type="text/css" rel="stylesheet"/>
	<script src="js/jquery-3.4.1.min.js" type="text/javascript"></script>
	<script src="js/jquery-ui-1.12.1.min.js" type="text/javascript"></script>
	<script src="js/!script.js" type="text/javascript"></script>
	<link href="css/!style.css" type="text/css" rel="stylesheet"/>
	<script src="js/i18n/grid.locale-kr.js" type="text/javascript"></script> 
	<script src="js/jquery.jqGrid.src.js" type="text/javascript"></script>
	<link href="css/ui.jqgrid.css" rel="stylesheet" type="text/css"/>

	<script src="js/sso-common.js" type="text/javascript"></script>
	<link href="./css/sso-common.css" rel="stylesheet" type="text/css"/>
	<link href="./css/sso-auditpolicy.css?v=2" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>

		<div class="page-breadcrumb">
			HOME / 감사 정책 / 감사 정책
		</div>
		<div class="page-header">
			<h4 class="title">감사 정책</h4>
		</div>

		<div class="content-box width-50p">
			<div class="content-top">
				<div class="float-left">
					<button class="subtitle-btn" type="button"></button>
					<span class="subtitle-text">감사 정책 정보</span>
				</div>
				<div class="float-right">
					<button class="btn" type="button" id="getAudit">초기화</button>
					<button class="btn ml-5" type="button" id="setAuditInfo">저 장</button>
				</div>
			</div>
			<div class="content-body pb-15">
				<table id="info">
					<colgroup>
						<col width="40%"/>
						<col width="60%"/>
					</colgroup>
					<tr>
						<td id="colnm">저장 용량 임계치</td>
						<td id="coldata">
							<input class="right_input" type="text" id="warnLimit" maxlength="2" style="width:60px"/>&nbsp;&nbsp;% 초과 시 메일 통보
						</td>
					</tr>
					<tr id="integ">
						<td class="tdlast" id="colnm">모듈 검증 주기<br/>&nbsp;&nbsp;- 암호모듈 자가시험<br/>&nbsp;&nbsp;- SSO모듈 무결성 검증<br/>&nbsp;&nbsp;- SSO프로세스 확인</td>
						<td class="tdlast" id="coldata" style="padding-top:3px;">
							<input type="radio" id="mCyle" name="verifyCycle" value="M" checked="checked" style="cursor:pointer; height:30px;"/>
							<label for="mCyle" style="cursor:pointer; vertical-align:middle;">&nbsp;매시&nbsp;&nbsp;
								<input class="right_input" type="text" id="verifyMPoint" maxlength="2" style="width:60px;margin-top:3px;"/>
								&nbsp;&nbsp;분에&nbsp;&nbsp;수행
							</label><br/>
							<input type="radio" id="hCyle" name="verifyCycle" value="H" style="cursor:pointer; height:30px;"/>
							<label for="hCyle" style="cursor:pointer; vertical-align:middle;">&nbsp;매일&nbsp;&nbsp;
								<input class="right_input" type="text" id="verifyHPoint" maxlength="2" style="width:60px;margin-top:3px;"/>
								&nbsp;&nbsp;시에&nbsp;&nbsp;수행
							</label><br/>
							<input type="radio" id="dCyle" name="verifyCycle" value="D" style="cursor:pointer; height:30px;"/>
							<label for="dCyle" style="cursor:pointer; vertical-align:middle;">&nbsp;매월&nbsp;&nbsp;
								<input class="right_input" type="text" id="verifyDPoint" maxlength="2" style="width:60px;margin-top:3px;"/>
								&nbsp;&nbsp;일에&nbsp;&nbsp;수행
							</label>
						</td>
					</tr>
				</table>
			</div>
		</div>
	</div>

<script type="text/javascript">
	$(document).ready(function(){
		checkAdmin();
		getAuditInfo();
	});

	$(window).resize(function(){
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

	$("#warnLimit").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#verifyMPoint").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#verifyHPoint").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#verifyDPoint").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});

	$("#setAuditInfo").click(function() {
		this.blur();
		var warnlimit = $("#warnLimit").val();
		var verifycycle = $("input:radio[name='verifyCycle']:checked").val();
		var verifypoint = "";
		var ch = $("#challenge").val();

		if (verifycycle == 'M') {
			verifypoint = $("#verifyMPoint").val();
			$("#verifyHPoint").val("");
			$("#verifyDPoint").val("");
		}
		else if (verifycycle == 'H') {
			verifypoint = $("#verifyHPoint").val();
			$("#verifyMPoint").val("");
			$("#verifyDPoint").val("");
		}
		else if (verifycycle == 'D') {
			verifypoint = $("#verifyDPoint").val();
			$("#verifyMPoint").val("");
			$("#verifyHPoint").val("");
		}
		else
			;

		if (warnlimit == null || warnlimit == "") {
			alert(" [저장 용량 임계치]  입력하세요.");
			$("#warnLimit").focus();
			return;
		}

		var nWarn = parseInt(warnlimit);
		if (nWarn < 50 || nWarn > 90) {
			alert(" 메일 통보 대상 임계치는 50 ~ 90 사이의 정수값를 입력하세요.");
			$("#warnLimit").focus();
			return;
		}
		else {
			$("#warnLimit").val("" + nWarn);
			warnlimit = $("#warnLimit").val();
		}

		if (verifypoint == null || verifypoint == "") {
			alert(" 모듈 검증 주기 - 수행 시점을 입력하세요.");
			if (verifycycle == 'M')
				$("#verifyMPoint").focus();
			else if (verifycycle == 'H')
				$("#verifyHPoint").focus();
			else if (verifycycle == 'D')
				$("#verifyDPoint").focus();
			else
				;
			return;
		}

		var nVerifypoint = parseInt(verifypoint);
		if (verifycycle == 'M') {
			if (nVerifypoint < 0 || nVerifypoint > 59) {
				alert(" 모듈 검증 주기 - 매시 수행은 0 ~ 59 사이의 정수값를 입력하세요.");
				$("#verifyMPoint").focus();
				return;
			}
			else {
				$("#verifyMPoint").val("" + nVerifypoint);
				verifypoint = $("#verifyMPoint").val();
			}
		}
		else if (verifycycle == 'H') {
			if (nVerifypoint < 0 || nVerifypoint > 23) {
				alert(" 모듈 검증 주기 - 매일 수행은 0 ~ 23 사이의 정수값를 입력하세요.");
				$("#verifyHPoint").focus();
				return;
			}
			else {
				$("#verifyHPoint").val("" + nVerifypoint);
				verifypoint = $("#verifyHPoint").val();
			}
		}
		else if (verifycycle == 'D') {
			if (nVerifypoint < 1 || nVerifypoint > 28) {
				alert(" 모듈 검증 주기 - 매월 수행은 1 ~ 28 사이의 정수값를 입력하세요.");
				$("#verifyDPoint").focus();
				return;
			}
			else {
				$("#verifyDPoint").val("" + nVerifypoint);
				verifypoint = $("#verifyDPoint").val();
			}
		}
		else
			;

		if (!confirm(" [감사 설정]  저장하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setAupyInfo.jsp",
			data: {ch:ch, warnlimit:warnlimit, verifycycle:verifycycle, verifypoint:verifypoint},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" [감사 설정]  저장 완료");
				}
				else if (resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus == -8) {
					alert(" 처리 권한이 없습니다.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
					alert(" [감사 설정]  저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#getAudit").click(function() {
		this.blur();
		getAuditInfo();
	});

	function clearAupyInfo()
	{
		$("#warnLimit").val("");
		$("#verifyMPoint").val("");
		$("#verifyHPoint").val("");
		$("#verifyDPoint").val("");
	}

	function getAuditInfo()
	{
		$.ajax({
			type: "POST",
			url: "sub/getAupyInfo.jsp",
			dataType: "JSON",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];
					clearAupyInfo();
					$("#warnLimit").val(result.warnLimit);
					$("input:radio[name='verifyCycle'][value='"+ result.verifyCycle +"']").prop("checked", true);
					if (result.verifyCycle == 'M')
						$("#verifyMPoint").val(result.verifyPoint);
					else if (result.verifyCycle == 'H')
						$("#verifyHPoint").val(result.verifyPoint);
					else if (result.verifyCycle == 'D')
						$("#verifyDPoint").val(result.verifyPoint);
					else
						;
				}
				else {
					alert(" [감사 설정] 조회 오류");
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	}

</script>
</body>
</html>