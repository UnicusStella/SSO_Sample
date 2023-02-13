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
	<link href="./css/sso-admininfo.css?v=1" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>
		<input type="hidden" id="newflag" value="U">
		<input type="hidden" id="getInfoflag" value=-1>

		<div class="page-breadcrumb">
			HOME / 관리자 / 관리자 관리
		</div>
		<div class="page-header">
			<h4 class="title">관리자 관리</h4>
		</div>

		<div class="d-flex">
			<div class="content-box width-50p mr-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">관리자 리스트</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="removeAdmn">삭 제</button>
					</div>
				</div>
				<div class="content-body pb-15" id="adminlist-box">
					<table id="adminList"></table>
				</div>
			</div>

			<div class="content-box width-50p ml-10">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">관리자 정보</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="newAdmn">신 규</button>
						<button class="btn ml-5" type="button" id="setAdmn">저 장</button>
					</div>
				</div>
				<div class="content-body pb-15">
					<table id="info">
						<colgroup>
							<col style="width:22%;">
							<col style="width:78%;">
						</colgroup>
						<tr>
							<td id="colnm">이름</td>
							<td id="coldata">
								<input class="basic_input" type="text" id="admnName" maxlength="50"/>
							</td>
						</tr>
						<tr>
							<td id="colnm">아이디</td>
							<td id="coldata">
								<input class="basic_input" type="text" id="admnId" maxlength="16" style="ime-mode:inactive"/>
							</td>
						</tr>
						<tr>
							<td id="colnm">비밀번호</td>
							<td id="coldata">
								<input class="basic_input" type="password" id="newPwd" maxlength="16"/>
							</td>
						</tr>
						<tr>
							<td id="colnm">비밀번호 확인</td>
							<td id="coldata">
								<input class="basic_input" type="password" id="chkPwd" maxlength="16"/>
							</td>
						</tr>
						<tr>
							<td id="colnm">구분</td>
							<td id="coldata">
								<div>
									<input type="radio" id="super" name="admnType" value="S" checked="checked" style="cursor:pointer;"/>
									<label for="super" style="cursor:pointer; vertical-align:middle;">최고관리자</label>
									<input type="radio" id="normal" name="admnType" value="N" style="cursor:pointer; margin-left:30px;"/>
									<label for="normal" style="cursor:pointer; vertical-align:middle;">모니터링관리자</label>
								</div>
							</td>
						</tr>
						<tr>
							<td id="colnm">이메일</td>
							<td id="coldata">
								<input class="basic_input" type="text" id="email" maxlength="50" style="ime-mode:inactive"/>
							</td>
						</tr>
						<tr>
							<td class="tdlast" id="colnm" style="padding-top:5px; vertical-align:top;">접근 권한</td>
							<td class="tdlast" id="coldata">
								<div class="menu_role" id="menu_check">
								</div>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	$(document).ready(function(){
		checkAdmin();

		clearAdmnInfo();
		$("#newflag").val("N");

		$("#adminList").jqGrid({
			url: "sub/getAdminList.jsp",
			datatype: "json",
			colNames: ['이름', '아이디', '구분', ''],
		    colModel: [
		          {name:'name', index:'name', width:'35%', align:'center', sortable:false},
		  	      {name:'id', index:'id', width:'40%', align:'center', sortable:false},
		  	      {name:'typeText', index:'typeText', width:'25%', align:'center', sortable:false},
		  	      {name:'type', index:'type', width:0, hidden:true}
			],
			id: 'id',
		    rowNum: 1000000,
		    gridview: true,
			scrollrows: true,
			loadonce: true,
			sortable: true,
			sortname: 'name',
		    height: 521,
		    loadtext: 'Loading...',
			onSelectRow: function() {
				if ($("#getInfoflag").val() == -1)
					getAdmnInfo();
				else
					$("#getInfoflag").val(-1);
			},
		    loadComplete:function(){
				$('#adminList').setGridWidth($('#adminlist-box').width(), true);

				var code = $("#admnId").val();
				if (code != "" && code != null) {
					if ($("#adminList").getInd(code) != false) {
						$("#getInfoflag").val(9);
						$("#adminList").setSelection(code);
					}
				}
		    },
			loadError: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		}).setGridWidth($('#adminlist-box').width(), true);
	});

	$(window).ready(function() {
		$('#admnName').css('width', $('#admnName').parent().width() - 20);
		$('#admnId').css('width', $('#admnId').parent().width() - 20);
		$('#newPwd').css('width', $('#newPwd').parent().width() - 20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width() - 20);
		$('#email').css('width', $('#email').parent().width() - 20);
	});

	$(window).resize(function() {
		$('#adminList').setGridWidth($('#adminlist-box').width(), true);

		$('#admnName').css('width', $('#admnName').parent().width() - 20);
		$('#admnId').css('width', $('#admnId').parent().width() - 20);
		$('#newPwd').css('width', $('#newPwd').parent().width() - 20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width() - 20);
		$('#email').css('width', $('#email').parent().width() - 20);
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

	$("#admnId").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^a-z0-9]/g, '');
		}
	});

	$("#email").keyup(function(e) {
		event = e || window.event;
		var keyID = event.which ? event.which : event.keyCode;
		if (keyID == 37 || keyID == 39 || keyID == 8 || keyID == 46) {  // 37=left 39=right 8=BackSpace 46=Delete
		}
		else {
			event.target.value = event.target.value.replace(/[^a-z0-9.@]/g, '');
		}
	});

	$("#newAdmn").click(function() {
		$("#adminList").resetSelection();
		clearAdmnInfo();
		$("#admnName").focus();
		$("#newflag").val("N");
	});

	$("#removeAdmn").click(function() {
		this.blur();

		var id = $("#adminList").getGridParam("selrow");
		var row = $("#adminList").getRowData(id);
		var ch = $("#challenge").val();

		if (row.id == "" || row.id == null) {
			alert(" 관리자를 선택하세요.");
			return;
		}

		if (row.id == "ssoadmin") {
			alert(" 관리자[ssoadmin] 계정은 삭제할 수 없습니다.");
			return;
		}

		if (row.id == $("#adminid").val()) {
			alert(" 로그인한 관리자 계정은 삭제할 수 없습니다.");
			return;
		}

		if (confirm(" " + row.name+" ["+row.id+"]  삭제하시겠습니까?")) {
			$.ajax({
				type: "POST",
				url: "sub/removeAdminInfo.jsp",
				data: {ch:ch, uid:row.id},
				dataType: "JSON",
				async: false,
				success: function(data) {
					var resultstatus = data.rows[0].resultstatus;
					if (resultstatus == 1) {
						$("#adminList").delRowData(row.id);
						clearAdmnInfo();
						$("#newflag").val("N");
						$("#adminList").setGridParam({datatype:"local"}).trigger("reloadGrid");
						alert(" 삭제 완료");
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
						alert(" ID: " + row.id + " 삭제 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
					}
				},
				error: function(xhr, status, error) {
					ajaxerror(xhr, status, error);
				}
			});
		}
	});

	$("#setAdmn").click(function(){
		this.blur();
		var newflag = $("#newflag").val() == "N" ? "1" : "0";
		var name = XSSCheck($("#admnName").val().trim());
		var uid = $("#admnId").val().trim();
		var newpwd = $("#newPwd").val();
		var chkpwd = $("#chkPwd").val();
		var type = $("input:radio[name='admnType']:checked").val();
		var typeText = convTypeText(type);
		var email = XSSCheck($("#email").val().trim());
		var menucode = "";
		var ch = $("#challenge").val();

		$("#admnName").val(name);
		$("#admnId").val(uid);
		$("#email").val(email);

		if (name == null || name == "") {
			alert(" [이름]  입력하세요.");
			$("#admnName").focus();
			return;
		}

		if (uid == null || uid == "") {
			alert(" [아이디]  입력하세요.");
			$("#admnId").focus();
			return;
		}

		if (newflag == "1") {
			format = /^[A-Za-z0-9]{8,16}$/;
			if (!format.test(uid)) {
				alert(" 관리자 아이디는 8 ~ 16자의 영문자, 숫자로 입력하세요.");
				$("#admnId").focus();
				return;
			}

			var ind = $("#adminList").getInd(uid);
			if (ind > 0) {
				alert(" 등록된 관리자 아이디입니다.");
				$("#admnId").focus();
				return;
			}

			if (newpwd == null || newpwd == "") {
				alert(" [비밀번호]  입력하세요.");
				$("#newPwd").focus();
				return;
			}

			format = /^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{9,16}$/;
			if (!format.test(newpwd)) {
				alert(" [비밀번호]  다음 규칙으로 입력하세요.\n\n 9 ~ 16자의 영문자, 숫자, 특수문자(!@#$%^*+=-)를 조합");
				$("#newPwd").focus();
				return;
			}

			if (chkpwd == null || chkpwd == "") {
				alert(" [비밀번호 확인]  입력하세요.");
				$("#chkPwd").focus();
				return;
			}

			if (newpwd != chkpwd) {
				alert(" [비밀번호]와  [비밀번호 확인]이 일치하지 않습니다.");
				$("#chkPwd").focus();
				return;
			}
		}

// 		if (email == "") {
// 			alert(" 이메일 주소를 입력하세요.");
// 			$("#email").focus();
// 			return;
// 		}

		if (type == "S")
			menucode = "";
		else
			menucode = "0101;0103;0104;0105;0403;0404;";

		if (!confirm(" " + name+" ["+uid+"]  저장하시겠습니까?"))
			return;

		$.ajax({
			type: "POST",
			url: "sub/setAdminInfo.jsp",
			data: {ch:ch, newflag:newflag, uid:uid, name:name, pwd:newpwd, type:type, email:email, menucode:menucode},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					if ($("#newflag").val() == "N") {
						$("#newflag").val("U");
						$("#newPwd").val("");
						$("#chkPwd").val("");
						$("#admnId").prop("disabled", true);
						$("#newPwd").prop("disabled", true);
						$("#chkPwd").prop("disabled", true);
						var newRowData = {'name':name, 'id':uid, 'type':type, 'typeText':typeText};
	      				$("#adminList").addRowData(uid, newRowData, "last");
						$("#adminList").setGridParam({datatype:'local'}).trigger("reloadGrid");
					}
					else {
						$("#adminList").setCell(uid, 'name', name);
						$("#adminList").setCell(uid, 'typeText', typeText);
						$("#adminList").setCell(uid, 'type', type);
					}

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
					alert(" ID: " + row.id + " 저장 오류 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#super").click(function(){
		setAccessRole("S");
	});

	$("#normal").click(function(){
		setAccessRole("N");
	});

	$("#admnName").keydown(function(e) {
		if (e.keyCode == 13)
			$("#admnId").focus();
	});
	$("#admnId").keydown(function(e) {
		if (e.keyCode == 13)
			$("#newPwd").focus();
	});
	$("#newPwd").keydown(function(e) {
		if (e.keyCode == 13)
			$("#chkPwd").focus();
	});
	$("#chkPwd").keydown(function(e) {
		if (e.keyCode == 13)
			$("#email").focus();
	});

	function clearAdmnInfo()
	{
		$("#admnName").val("");
		$("#admnId").val("");
		$("#newPwd").val("");
		$("#chkPwd").val("");
		$("#admnId").prop("disabled", false);
		$("#newPwd").prop("disabled", false);
		$("#chkPwd").prop("disabled", false);
		$("#normal").prop("checked", true);
		$("#email").val("");
		$("input[type=radio]").prop("disabled", false);
		setAccessRole("N");
	}

	function getAdmnInfo()
	{
		var id = $("#adminList").getGridParam("selrow");

		$.ajax({
			type: "POST",
			url: "sub/getAdminInfo.jsp",
			data: {uid: id},
			dataType: "json",
			async: false,
			success: function(data) {
				if (data != null && data.rows.length == 1) {
					var result = data.rows[0];
					var row = $("#adminList").getRowData(id);

					clearAdmnInfo();
					$("#admnName").val(result.name);
					$("#admnId").val(result.id);
					$("#admnId").prop("disabled", true);
					$("#newPwd").prop("disabled", true);
					$("#chkPwd").prop("disabled", true);
					$("input:radio[name='admnType'][value='"+ row.type +"']").prop("checked", true);
					$("#email").val(result.email);
					setCheckBox(row.id, row.type, result.menuCode);

					$("#newflag").val("U");
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

	function setCheckBox(admnId, adminType, menuCode)
	{
		if (admnId == "ssoadmin" || admnId == $("#adminid").val()) {
			$("input[type=radio]").prop("disabled", true);
		}
		else {
			$("input[type=radio]").prop("disabled", false);
		}

		setAccessRole(adminType);
	}

	function setAccessRole(adminType)
	{
		var innerHtml = "";

		if (adminType == "S") {
			innerHtml += "감사 정보<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 감사 정보 조회<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 접속 정보 조회<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 접속 정보 통계<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 실시간 모듈 검증<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 서버 모니터링<br>";
			innerHtml += "감사 정책<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 감사 정책<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 메일 통보 설정<br>";
			innerHtml += "사용자<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 사용자 정책<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 사용자 잠김 해제<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 사용자 강제 로그아웃<br>";
			innerHtml += "관리자<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 관리자 관리<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 관리자 정책<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 비밀번호 변경<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 제품 버전 정보<br>";
			innerHtml += "클라이언트<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 클라이언트 관리<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Scope 관리";
		}
		else {
			innerHtml += "감사 정보<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 감사 정보 조회<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 접속 정보 조회<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 접속 정보 통계<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 서버 모니터링<br>";
			innerHtml += "관리자<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 비밀번호 변경<br>";
			innerHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- 제품 버전 정보";
		}

		$("#menu_check").html(innerHtml);
	}

	function convTypeText(type)
	{
		var rtn = "";

		if (type != null && type == "S")
			rtn = "최고관리자";
		else if (type != null && type == "N")
			rtn = "모니터링관리자";
		else
			rtn = "";

		return rtn;
	}
</script>
</body>
</html>
