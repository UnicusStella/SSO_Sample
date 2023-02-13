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
	<link href="./css/sso-userpwd.css?v=1" rel="stylesheet" type="text/css"/>
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="challenge" value="<%=XSSCheck(challenge)%>"/>
		<input type="hidden" id="hstype" value=""/>
		<input type="hidden" id="hsvalue" value=""/>
		<input type="hidden" id="pageRow" value=20>
		<input type="hidden" id="totalCnt" value=0>
		<input type="hidden" id="curPage" value=1>

		<div class="page-breadcrumb">
			HOME / 사용자 / 사용자 비밀번호 변경
		</div>
		<div class="page-header">
			<h4 class="title">사용자 비밀번호 변경</h4>
		</div>
		<div class="d-flex">
			<div class="content-box width-50p mr-10">
				<div class="content-top">
					<div class="float-right">
						<select class="search-base" id="searchtype">
					    	<option value="1" selected="selected">이름</option>
					    	<option value="2">아이디</option>
						</select>
						<input class="search-input width-200 ml-5" type="text" id="searchtext" maxlength="20" placeholder="검색"/>
						<input class="search-btn" type="button" id="searchBtn"/>
					</div>
				</div>
				<div class="content-body pb-10">
					<table id="datagrid"></table>
				</div>
				<div class="content-bottom">
					<div class="float-left">
						<div class="total-count" id="total-tag"></div>
					</div>
					<div class="float-right" id="page-tag"></div>
				</div>
			</div>

			<div class="content-box width-50p">
				<div class="content-top">
					<div class="float-left">
						<button class="subtitle-btn" type="button"></button>
						<span class="subtitle-text">비밀번호 변경</span>
					</div>
					<div class="float-right">
						<button class="btn" type="button" id="setUserPwd">저 장</button>
					</div>
				</div>
				<div class="content-body">
					<table id="info">
						<colgroup>
							<col width="30%"/>
							<col width="70%"/>
						</colgroup>
						<tr>
							<td id="colnm">새 비밀번호</td>
							<td id="coldata">
								<input class="basic_input" type="password" id="newPwd" maxlength="16"/>
							</td>
						</tr>
						<tr>
							<td class="tdlast" id="colnm">새 비밀번호 확인</td>
							<td class="tdlast" id="coldata">
								<input class="basic_input" type="password" id="chkPwd" maxlength="16"/>
							</td>
						</tr>
					</table>
				</div>
				<div class="content-bottom">
					<div class="cont-bottom-left alert">
					###&nbsp;&nbsp;&nbsp;비밀번호는 9 ~ 16자의 영문자, 숫자, 특수문자(!@#$%^*+=-)를 조합하여 사용합니다.&nbsp;&nbsp;&nbsp;###
					</div>
				</div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	var first_flag = 1;

	$(document).ready(function(){
		checkAdmin();

		$('#searchtype').change(function() {
			$('#searchtext').focus();
		});

		$('#searchtext').focus();

		$('#newPwd').css('width', $('#newPwd').parent().width()-20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width()-20);
	});

	$(window).resize(function(){
		$('#datagrid').setGridWidth($('.content-body').width(), true);
		$('#newPwd').css('width', $('#newPwd').parent().width()-20);
		$('#chkPwd').css('width', $('#chkPwd').parent().width()-20);
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

	$("#datagrid").jqGrid({
		datatype: "local",
		jsonReader: {
			page: "page",
			total: "total",
			root: "rows",
			records: function(obj) {return obj.length;},
			repeatitems: false,
			id: "id"
		},
		colNames: ['No', '이름', '아이디', '상태'],
	    colModel: [
			{name:'index', index:'index', width:'7%', align:'center', sortable:false},
			{name:'name', index:'name', width:'19%', align:'center', sortable:false},
			{name:'id', index:'id', width:'19%', align:'center', sortable:false},
			{name:'statusNm', index:'statusNm', width:'8%', align:'center', sortable:false}
		],
		id: 'id',
	    rowNum: 10000000,
		gridview: true,
	    sortable: false,
	    height: 521,
	    loadtext: 'Loading...',
	    beforeProcessing: function (data) {
	    	$('#totalCnt').val(data.total);
	    },
	    loadComplete: function(data) {
			$('#datagrid').setGridWidth($('.content-body').width(), true);

			if (first_flag != "1") {
				var ids = $("#datagrid").getDataIDs();
				if (ids.length == 0) {
					$('#curPage').val(1);
					alert(" 조회 자료가 없습니다.");
				} else {
					$("#hstype").val($("#searchtype option:selected").val());
					var svalue = $("#searchtext").val().toLowerCase();
					$("#hsvalue").val($.trim(svalue));
				}
			}
			else {
				first_flag = "0";
			}

			setPageTag($('#totalCnt').val(), $('#curPage').val());
	    },
	  	loadError: function(xhr, status, error) {
	  		ajaxerror(xhr, status, error);
	    }
	}).setGridWidth($('.content-body').width(), true);

	$("#searchBtn").click(function() {
		goSearch();
	});

	$("#searchtext").keypress(function(e) {
		if (e.which == 13) {
			goSearch();
		}
	});

	function goSearch()
	{
		var pagerow = $("#pageRow").val();
		var stype = $("#searchtype option:selected").val();
		var svalue = $("#searchtext").val().toLowerCase();
		$("#searchtext").val($.trim(svalue));
		svalue = $.trim(svalue);

		$("#curPage").val(1);

		$("#datagrid").setGridParam({ datatype:"json" });
		$("#datagrid").setGridParam({ url:"sub/getUserListByVal.jsp", mtype:"POST", postData:{stype:stype, svalue:svalue, spage:1, pagerow:pagerow} });
		$("#datagrid").trigger("reloadGrid");
	}

	function pageSearch(pageNo)
	{
		var pagerow = $("#pageRow").val();
		var stype = $("#searchtype option:selected").val();
		var svalue = $("#searchtext").val().toLowerCase();
		svalue = $.trim(svalue);

		if (stype != $("#hstype").val()) {
			alert(" 조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}

		if (svalue != $("#hsvalue").val()) {
			alert(" 조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}

		$("#curPage").val(pageNo);

		$("#datagrid").setGridParam({ datatype:"json" });
		$("#datagrid").setGridParam({ url:"sub/getUserListByVal.jsp", mtype:"POST", postData:{stype:stype, svalue:svalue, spage:pageNo, pagerow:pagerow} });
		$("#datagrid").trigger("reloadGrid");
	}

	function setPageTag(totalCnt, curPage)
	{
		var maxRows = $("#pageRow").val();
		var maxPages = 10;
		var tagString = "";

		if (totalCnt <= 0) {
			tagString += "<a class='first paginate_button_disabled'></a>";
			tagString += "<a class='previous paginate_button_disabled'></a>";
			tagString += "<a class='paginate_active'>1</a>";
			tagString += "<a class='next paginate_button_disabled'></a>";
			tagString += "<a class='last paginate_button_disabled'></a>";
			$("#total-tag").text("전체 0 건");
			$("#page-tag").html(tagString);
			return;
		}

		var pageCnt = parseInt((totalCnt - 1) / maxRows) + 1;
		var fromPage = parseInt((curPage - 1) / maxPages) * maxPages + 1;
		var toPage = fromPage + maxPages - 1;
		if (toPage > pageCnt)
			toPage = pageCnt;

		if (curPage > maxPages) {
			tagString += "<a class='first paginate_button' href='javascript:pageSearch(1);' title='맨 앞'></a>";
			tagString += "<a class='previous paginate_button' href='javascript:pageSearch(" + (fromPage - 1) + ");' title='이전'></a>";
		}
		else {
			tagString += "<a class='first paginate_button_disabled'></a>";
			tagString += "<a class='previous paginate_button_disabled'></a>";
		}
		for (var i = fromPage; i <= toPage; i++) {
			if (i == curPage)
				tagString += "<a class='paginate_active'>" + i + "</a>";
			else
				tagString += "<a class='paginate_button' href='javascript:pageSearch(" + i + ");'>" + i + "</a>";
		}
		if (toPage < pageCnt) {
			tagString += "<a class='next paginate_button' href='javascript:pageSearch(" + (toPage + 1) + ");' title='다음'></a>";
			tagString += "<a class='last paginate_button' href='javascript:pageSearch(" + pageCnt + ");' title='맨 뒤'></a>";
		}
		else {
			tagString += "<a class='next paginate_button_disabled'></a>";
			tagString += "<a class='last paginate_button_disabled'></a>";
		}

		var cnt = totalCnt.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
		$("#total-tag").text("전체  " + cnt + " 건");

		$("#page-tag").html(tagString);
	}
	
	$("#setUserPwd").click(function() {
		this.blur();
		var id = $("#datagrid").getGridParam('selrow');
		var row = $("#datagrid").getRowData(id);
		var name = row.name;
		var newpwd = $("#newPwd").val();
		var chkpwd = $("#chkPwd").val();
		var ch = $("#challenge").val();

		if (id == "" || id == null) {
			alert(" 사용자를 선택하세요.");
			return;
		}

		if (newpwd == null || newpwd == "") {
			alert(" [새 비밀번호]  입력하세요.");
			$("#newPwd").focus();
			return;
		}
		if (chkpwd == null || chkpwd == "") {
			alert(" [새 비밀번호 확인]  입력하세요.");
			$("#chkPwd").focus();
			return;
		}

		format = /^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{9,16}$/;
		if (!format.test(newpwd)) {
			alert(" [새 비밀번호]를 규칙에 맞게 입력하세요.");
			$("#newPwd").focus();
			return;
		}

		if (newpwd != chkpwd) {
			alert(" [새 비밀번호]와  [새 비밀번호 확인]이 일치하지 않습니다.");
			$("#chkPwd").focus();
			return;
		}

		$.ajax({
			type: "POST",
			url: "sub/setUserChangePwd.jsp",
			data: {ch:ch, uid:id, pwd:newpwd, name:name},
			dataType: "JSON",
			async: false,
			success: function(data) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus == 1) {
					$("#newPwd").val("");
					$("#chkPwd").val("");
					goSearch();
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
					alert(" 저장 실패 (" + resultstatus + ")\n\n" + data.rows[0].resultdata);
				}
			},
			error: function(xhr, status, error) {
				ajaxerror(xhr, status, error);
			}
		});
	});

	$("#newPwd").keydown(function(e) {
		if (e.keyCode == 13)
			$("#chkPwd").focus();
	});

</script>
</body>
</html>