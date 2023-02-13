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
	<link href="./css/sso-userpolicy.css?v=1" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>

		<div class="page-breadcrumb">
			HOME / 사용자 / 사용자 정책
		</div>
		<div class="page-header">
			<h4 class="title">사용자 정책</h4>
		</div>

		<div class="content-box width-50p">
			<div class="content-top">
				<div class="float-left">
					<button class="subtitle-btn" type="button"></button>
					<span class="subtitle-text">사용자 정책 정보</span>
				</div>
				<div class="float-right">
					<button class="btn" type="button" id="getUrpy">초기화</button>
					<button class="btn ml-5" type="button" id="setUrpyInfo">저 장</button>
				</div>
			</div>
			<div class="content-body pb-15">
				<table id="info">
					<colgroup>
						<col width="35%">
						<col width="65%">
					</colgroup>
					<tr>
						<td id="colnm">비밀번호 실패 허용 회수</td>
						<td id="coldata">
							<input class="right_input" type="text" id="pwMismatchAllow" style="width:60px;" maxlength="4"/>&nbsp;회 연속 실패시 로그인 불가
						</td>
					</tr>
					<tr>
						<td id="colnm">비밀번호 유효 기간</td>
						<td id="coldata">
							<input class="right_input" type="text" id="pwValidate" style="width:60px;" maxlength="4"/>&nbsp;일 초과시 비밀번호 강제 변경
						</td>
					</tr>
					<tr>
						<td id="colnm">비밀번호 만료 경고</td>
						<td id="coldata">만료일&nbsp;
							<input class="right_input" type="text" id="pwChangeWarn" style="width:60px;" maxlength="4"/>&nbsp;일 전 만료 경고 알림
						</td>
					</tr>
					<!-- tr>
						<td id="colnm">중복 로그인 체크 주기</td>
						<td id="coldata">
							<input class="right_input" type="text" id="pollingTime" style="width:60px;" maxlength="4"/>&nbsp;초 마다 중복 로그인 체크
						</td>
					</tr -->
					<tr>
						<td class="tdlast" id="colnm">세션 비활동 시간</td>
						<td class="tdlast" id="coldata">
							<input class="right_input" type="text" id="sessionTime" style="width:60px;" maxlength="4"/>&nbsp;분 동안 미사용시 로그아웃
						</td>
					</tr>
				</table>
			</div>
		</div>
	</div>

<script type="text/javascript">
	$(document).ready(function(){
		checkAdmin();
		getUrpyInfo();
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

	$("#setUrpyInfo").click(function() {
		this.blur();
		var pwcnt = $("#pwMismatchAllow").val();
		var pwvalid = $("#pwValidate").val();
		var pwwarn = $("#pwChangeWarn").val();
		var polltime = 60; //$("#pollingTime").val();
		var sesstime = $("#sessionTime").val();
		var ch = $("#challenge").val();

		if (pwcnt == null || pwcnt == "") {
			alert(" [비밀번호 실패 허용 회수]  입력하세요.");
			$("#pwMismatchAllow").focus();
			return;
		}

		var nPwcnt = parseInt(pwcnt);
		if (nPwcnt < 1 || nPwcnt > 5) {
			alert(" 비밀번호 실패 허용 회수는 1 ~ 5 사이의 정수값를 입력하세요.");
			$("#pwMismatchAllow").focus();
			return;
		}
		else {
			$("#pwMismatchAllow").val("" + nPwcnt);
			pwcnt = $("#pwMismatchAllow").val();
		}

		if (pwvalid == null || pwvalid == "") {
			alert(" [비밀번호 유효 기간]  입력하세요.");
			$("#pwValidate").focus();
			return;
		}

		if (pwwarn == null || pwwarn == "") {
			alert(" [비밀번호 만료 경고]  입력하세요.");
			$("#pwChangeWarn").focus();
			return;
		}

		var nValid = parseInt(pwvalid);
		var nWarn = parseInt(pwwarn);
		if (nWarn > nValid) {
			alert(" 비밀번호 만료 경고일보다 비밀번호 유효 기간이 커야 합니다.");
			$("#pwChangeWarn").focus();
			return;
		}
		else {
			$("#pwValidate").val("" + nValid);
			pwvalid = $("#pwValidate").val();

			$("#pwChangeWarn").val("" + nWarn);
			pwwarn = $("#pwChangeWarn").val();
		}

		/***
		if (polltime == null || polltime == "") {
			alert(" [중복 로그인 체크 주기]  입력하세요.");
			$("#pollingTime").focus();
			return;
		}
		else {
			var nPoll = parseInt(polltime);
			$("#pollingTime").val("" + nPoll);
			polltime = $("#pollingTime").val();
		}
		***/

		if (sesstime == null || sesstime == "") {
			alert(" [세션 비활동 시간]  입력하세요.");
			$("#sessionTime").focus();
			return;
		}

		var nSess = parseInt(sesstime);
		if (nSess < 3 || nSess > 10) {
			alert(" 세션 비활동 시간은 3 ~ 10 사이의 정수값를 입력하세요.");
			$("#sessionTime").focus();
			return;
		}
		else {
			$("#sessionTime").val("" + nSess);
			sesstime = $("#sessionTime").val();
		}

		if (!confirm(" 사용자 정책을 저장하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setUrpyInfo.jsp",
			data: {ch:ch, urpycode:"URPY0001", pwcnt:pwcnt, pwwarn:pwwarn, pwvalid:pwvalid, polltime:polltime, sesstime:sesstime},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					alert(" 저장 완료");
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
					alert(" ID: " + id + " 저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#pwMismatchAllow").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#pwChangeWarn").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	$("#pwValidate").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	/***
	$("#pollingTime").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});
	***/
	$("#sessionTime").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^0-9]/g, '');
		}
	});

	$("#pwMismatchAllow").keydown(function(e) {
		if (e.keyCode == 13)
			$("#pwValidate").focus();
	});
	$("#pwValidate").keydown(function(e) {
		if (e.keyCode == 13)
			$("#pwChangeWarn").focus();
	});
	$("#pwChangeWarn").keydown(function(e) {
		if (e.keyCode == 13)
			$("#sessionTime").focus();
	});
	/***
	$("#pollingTime").keydown(function(e) {
		if (e.keyCode == 13)
			$("#sessionTime").focus();
	});
	***/

	$("#getUrpy").click(function() {
		this.blur();
		getUrpyInfo()
	});

	function getUrpyInfo()
	{
		$.ajax({
			type: "POST",
			url: "sub/getUrpyInfo.jsp",
			data: {urpycode: "URPY0001"},
			dataType: "JSON",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];
					$("#pwMismatchAllow").val(result.pwMismatchAllow);
					$("#pwChangeWarn").val(result.pwChangeWarn);
					$("#pwValidate").val(result.pwValidate);
					//$("#pollingTime").val(result.pollingTime);
					$("#sessionTime").val(result.sessionTime);
				}
				else {
					alert(" 조회 오류");
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
