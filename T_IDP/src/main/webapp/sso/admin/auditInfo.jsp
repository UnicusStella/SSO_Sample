<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
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
</head>
<body>
	<div class="page-holder">
		<input type="hidden" id="adminid" value="<%=XSSCheck(adminid)%>"/>
		<input type="hidden" id="adminip" value="<%=XSSCheck(adminip)%>"/>
		<input type="hidden" id="currip" value="<%=XSSCheck(currip)%>"/>
		<input type="hidden" id="hfdate" value=""/>
		<input type="hidden" id="htdate" value=""/>
		<input type="hidden" id="hstype" value=""/>
		<input type="hidden" id="hresult" value=""/>
		<input type="hidden" id="pageRow" value=20>
		<input type="hidden" id="totalCnt" value=0>
		<input type="hidden" id="curPage" value=0>

		<div class="page-breadcrumb">
			HOME / 감사 정보 / 감사 정보 조회
		</div>
		<div class="page-header">
			<h4 class="title">감사 정보 조회</h4>
		</div>
		<div class="content-box">
			<div class="content-top">
				<div class="float-right">
					<input class="date-input" type="text" id="sel-fdate" title="조회 시작일"/>
					<span class="date-between">&nbsp;∼&nbsp;</span>
					<input class="date-input" type="text" id="sel-tdate" title="조회 종료일"/>
					<select class="search-base width-200 ml-10" id="sel-type">
					    <option value="00" selected="selected">전체 사건</option>
					    <option value="AA">감사 기능 시작/종료</option>
					    <option value="AE">감사정보 용량 임계치 초과</option>
					    <option value="AC">암호모듈 자가시험</option>
					    <option value="AD">SSO모듈 무결성 검증</option>
					    <option value="BB">SSO프로세스 확인</option>
					    <option value="AB">관리자 로그인 요청</option>
					    <option value="BC">관리자 로그아웃</option>
					    <option value="AG">사용자 로그인 요청</option>
					    <option value="BH">사용자 2차 인증 요청</option>
					    <option value="BD">사용자 로그아웃</option>
					    <option value="AH">사용자 연계 요청</option>
					    <option value="AI">사용자 비밀번호 변경</option>
					    <option value="AL">세션 비활동 시간 경과</option>
					    <option value="AY">메일 발송</option>
					    <option value="AF">감사정보 설정 변경</option>
					    <option value="AN">메일서버 설정 변경</option>
					    <option value="AO">메일정보 설정 변경</option>
					    <option value="BE">사용자 정보 변경</option>
					    <option value="AP">사용자 정책 변경</option>
					    <option value="AQ">사용자 잠김 해제</option>
					    <option value="AR">관리자 정보 변경</option>
					    <option value="AS">관리자 정책 변경</option>
					    <option value="AT">관리자 접속 IP 변경</option>
					    <option value="AU">관리자 비밀번호 변경</option>
					    <option value="BF">클라이언트 정보 변경</option>
					    <option value="BG">Scope 정보 변경</option>
					    <option value="AM">암호키 생성</option>
					    <option value="AV">암호키 분배</option>
					    <option value="AW">암호키 파기</option>
					    <option value="AX">암호 연산</option>
					    <option value="AZ">비밀정보 파기</option>
					    <option value="BA">인증토큰 생성</option>
					</select>
					<select class="search-base width-90 ml-10" id="sel-result">
					    <option value="A" selected="selected">전체 결과</option>
					    <option value="0">성공</option>
					    <option value="1">실패</option>
					</select>
					<button class="btn ml-10" type="button" id="searchBtn">조 회</button>
					<button class="btn ml-10" type="button" id="excelBtn">Excel</button>
				</div>
			</div>
			<div class="content-body pb-10">
				<table id="reportGrid"></table>
			</div>
			<div class="content-bottom">
				<div class="float-left">
					<div class="total-count" id="total-tag"></div>
				</div>
				<div class="float-right" id="page-tag"></div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	var first_flag = 1;

	$(document).ready(function() {
		checkAdmin();

		$("#sel-fdate").val(getCurrentDate());
		$("#sel-tdate").val(getCurrentDate());
	});

	$(window).resize(function(){
		$('#reportGrid').setGridWidth($('.content-body').width(), true);
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

	$(function() {
		$("#sel-fdate, #sel-tdate").datepicker({
			width: '14em',
			changeMonth: true,         // 월을 바꿀수 있는 셀렉트 박스를 표시한다.
			changeYear: true,          // 년을 바꿀 수 있는 셀렉트 박스를 표시한다.
			minDate: '-50y',          // 현재날짜로부터 100년이전까지 년을 표시한다.
			nextText: '다음 달',         // next 아이콘의 툴팁.
			prevText: '이전 달',         // prev 아이콘의 툴팁.
			numberOfMonths: [1,1],     // 한번에 얼마나 많은 월을 표시할것인가. [2,3] 일 경우, 2(행) x 3(열) = 6개의 월을 표시한다.
			stepMonths: 1,             // next, prev 버튼을 클릭했을때 얼마나 많은 월을 이동하여 표시하는가. 
			yearRange: 'c-50:c+10',   // 년도 선택 셀렉트박스를 현재 년도에서 이전, 이후로 얼마의 범위를 표시할것인가.
			currentText: '오늘 날짜' ,   // 오늘 날짜로 이동하는 버튼 패널
			dateFormat: "yy-mm-dd",    // 텍스트 필드에 입력되는 날짜 형식.
			showMonthAfterYear: true , // 월, 년순의 셀렉트 박스를 년,월 순으로 바꿔준다. 
			dayNamesMin: ['일', '월', '화', '수', '목', '금', '토'], // 요일의 한글 형식.
			monthNamesShort: ['1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월'] // 월의 한글 형식.
		});
	});

	$("#reportGrid").jqGrid({
		datatype: "local",
		jsonReader: {
			page: "page",
			total: "total",
			root: "rows",
			records: function(obj) {return obj.length;},
			repeatitems: false,
			id: "index"
		},
		colNames: ['No', '일시', '주체', '사건', '결과', '상세'],
	    colModel: [
			{name:'index', index:'index', width:'5%', align:'center', sortable:false},
			{name:'logDatetime', index:'logDatetime', width:'18%', align:'center', sortable:false},
			{name:'caseUser', index:'caseUser', width:'12%', align:'center', sortable:false},
			{name:'caseType', index:'caseType', width:'20%', align:'left', sortable:false},
			{name:'caseResult', index:'caseResult', width:'6%', align:'center', sortable:false},
			{name:'caseData', index:'caseData', width:'39%', align:'left', sortable:false}
		],
		id: 'index',
	    rowNum: 10000000,
		gridview: true,
	    sortable: false,
	    height: 521,
	    loadtext: 'Loading...',
	    beforeProcessing: function (data) {
	    	$('#totalCnt').val(data.total);
	    },
	    loadComplete: function(data) {
			$('#reportGrid').setGridWidth($('.content-body').width(), true);

			if (data.rows.length > 0) {
				var resultstatus = data.rows[0].resultstatus;
				if (resultstatus != null && resultstatus == -9) {
					alert(" 로그인 후 사용하세요.");
					parent.location.href = "<%=XSSCheck(LOGIN_PAGE)%>";
				}
				else if (resultstatus != null && resultstatus == -8) {
					alert(" 조회 권한이 없습니다.");
					parent.location.href = "<%=XSSCheck(ADMIN_MAIN_PAGE)%>";
				}
				else {
				}
			}

			if (first_flag != "1") {
				var ids = $("#reportGrid").getDataIDs();
				if (ids.length == 0) {
					$('#curPage').val(0);
					alert(" 조회 자료가 없습니다.");
				} else {
					$("#hfdate").val($("#sel-fdate").val());
					$("#htdate").val($("#sel-tdate").val());
					$("#hstype").val($("#sel-type option:selected").val());
					$("#hresult").val($("#sel-result option:selected").val());
				}
			} else {
				first_flag = "0";
			}

			setPageTag($('#totalCnt').val(), $('#curPage').val());
	    },
	  	loadError: function(xhr, status, error) {
	  		ajaxerror(xhr, status, error);
	    }
	}).setGridWidth($('.content-body').width(), true);

	$("#sel-fdate").keydown(function(e) {
		var keyID = e.which ? e.which : e.keyCode;
		if (keyID == 16 || keyID == 8) {  // 16=shift 8=BS
			return true;
		}
		else if (!e.shiftKey && (keyID >= 48 && keyID <= 57)) {  // number
		}
		else if (keyID >= 96 && keyID <= 105) {  // extend number
		}
		else {
			return false;
		}

		var size = $("#sel-fdate").val();
		if (size.length == 4)
			size += "-";
		if (size.length == 7)
			size += "-";
		if (size.length == 10)
			return false;
		$("#sel-fdate").val(size);
	});

	$("#sel-tdate").keydown(function(e) {
		var keyID = e.which ? e.which : e.keyCode;
		if (keyID == 16 || keyID == 8) {  // 16=shift 8=BS
			return true;
		}
		else if (!e.shiftKey && (keyID >= 48 && keyID <= 57)) {  // number
		}
		else if (keyID >= 96 && keyID <= 105) {  // extend number
		}
		else {
			return false;
		}

		var size = $("#sel-tdate").val();
		if (size.length == 4)
			size += "-";
		if (size.length == 7)
			size += "-";
		if (size.length == 10)
			return false;
		$("#sel-tdate").val(size);
	});

	$("#searchBtn").click(function(){
		search();
	});

	$("#excelBtn").click(function(){
		excel_search();
	});

	function search()
	{
		$("#hfdate").val("");
		$("#htdate").val("");
		$("#hstype").val("");
		$("#hresult").val("");

		format = /^(19|20)\d{2}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[0-1])$/;
		if (!format.test($("#sel-fdate").val())) {
			alert(" 조회 일자를 정확하게 입력하세요.");
			$("#sel-fdate").focus();
			return;
		}
		if (!format.test($("#sel-tdate").val())) {
			alert(" 조회 일자를 정확하게 입력하세요.");
			$("#sel-tdate").focus();
			return;
		}
		if ($("#sel-fdate").val() > $("#sel-tdate").val()) {
			alert(" [시작 조회 일자]가 [종료 조회 일자]보다 클 수 없습니다.");
			$("#sel-fdate").focus();
			return;
		}

		var fdate = $("#sel-fdate").val().replace(/-/g,'');
		var tdate = $("#sel-tdate").val().replace(/-/g,'');
		var stype = $("#sel-type option:selected").val();
		var srslt = $("#sel-result option:selected").val();

		var pagerow = $("#pageRow").val();
		$("#curPage").val(1);

		$("#reportGrid").setGridParam({ datatype:"json" });
		$("#reportGrid").setGridParam({ url:"sub/getAuditInfo.jsp", mtype:"POST", postData:{fdate:fdate, tdate:tdate, stype:stype, srslt:srslt, spage:1, pagerow:pagerow} });
		$("#reportGrid").trigger("reloadGrid");
	}

	function pageSearch(pageNo)
	{
		format = /^(19|20)\d{2}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[0-1])$/;
		if (!format.test($("#sel-fdate").val())) {
			alert("조회 일자를 정확하게 입력하세요.");
			$("#sel-fdate").focus();
			return;
		}
		if (!format.test($("#sel-tdate").val())) {
			alert("조회 일자를 정확하게 입력하세요.");
			$("#sel-tdate").focus();
			return;
		}
		if ($("#sel-fdate").val() != $("#hfdate").val()) {
			alert("조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}
		if ($("#sel-tdate").val() != $("#htdate").val()) {
			alert("조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}

		var fdate = $("#sel-fdate").val().replace(/-/g,'');
		var tdate = $("#sel-tdate").val().replace(/-/g,'');
		var stype = $("#sel-type option:selected").val();
		if (stype != $("#hstype").val()) {
			alert("조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}

		var srslt = $("#sel-result option:selected").val();
		if (srslt != $("#hresult").val()) {
			alert("조회 조건이 변경되었습니다.  [조회] 버튼을 클릭하세요.");
			return;
		}

		var pagerow = $("#pageRow").val();
		$("#curPage").val(pageNo);

		$("#reportGrid").setGridParam({ datatype:"json" });
		$("#reportGrid").setGridParam({ url:"sub/getAuditInfo.jsp", mtype:"POST", postData:{fdate:fdate, tdate:tdate, stype:stype, srslt:srslt, spage:pageNo, pagerow:pagerow} });
		$("#reportGrid").trigger("reloadGrid");
	}

	function getCurrentDate()
	{	// YYYY-MM-DD
		var now = new Date();      
		var nowDate = now.getFullYear() + "-";
		nowDate += now.getMonth()+1 < 10 ? "0" + (now.getMonth()+1) : now.getMonth()+1;
		nowDate += "-";
		nowDate += now.getDate() < 10 ? "0" + now.getDate() : now.getDate();
		return nowDate;
	}

	function setPageTag(totalCnt, curPage)
	{
		var maxRows = $("#pageRow").val();
		var maxPages = 10;
		var tagString = "";

		if (totalCnt == 0) {
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

	function excel_search()
	{
		format = /^(19|20)\d{2}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[0-1])$/;
		if (!format.test($("#sel-fdate").val())) {
			alert(" 조회 일자를 정확하게 입력하세요.");
			$("#sel-fdate").focus();
			return;
		}
		if (!format.test($("#sel-tdate").val())) {
			alert(" 조회 일자를 정확하게 입력하세요.");
			$("#sel-tdate").focus();
			return;
		}
		if ($("#sel-fdate").val() > $("#sel-tdate").val()) {
			alert(" [시작 조회 일자]가 [종료 조회 일자]보다 클 수 없습니다.");
			$("#sel-fdate").focus();
			return;
		}

		var fdate = $("#sel-fdate").val().replace(/-/g,'');
		var tdate = $("#sel-tdate").val().replace(/-/g,'');
		var stype = $("#sel-type option:selected").val();
		var srslt = $("#sel-result option:selected").val();

		$.ajax({
			type: "POST",
			url: "sub/getExcelAuditInfo.jsp",
			data: {fdate:fdate, tdate:tdate, stype:stype, srslt:srslt},
			dataType: "JSON",
			async: false,
			success: function(data) {
				if (data != null) {
					var rstatus = data.rows[0].resultstatus;

					if (rstatus == 1) {
						var filename = data.rows[0].resultdata;
						downExcel(filename);
					}
					else if (rstatus == -1) {
						alert(" 조회 자료가 없습니다.");
					}
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

	function downExcel(filename)
	{
		var browserName = undefined;
		var userAgent = navigator.userAgent;

		switch (true) {
		case /Trident|MSIE/.test(userAgent):
			browserName = 'ie';
			break;
		case /Edge/.test(userAgent):
			browserName = 'edge';
			break;
		case /Chrome/.test(userAgent):
			browserName = 'chrome';
			break;
		case /Safari/.test(userAgent):
			browserName = 'safari';
			break;
		case /Firefox/.test(userAgent):
			browserName = 'firefox';
			break;
		case /Opera/.test(userAgent):
			browserName = 'opera';
			break;
		default:
			browserName = 'unknown';
		}

		var url = "/sso/down/" + filename;

		if (browserName == 'ie' || browserName == 'edge') {
			var _window = window.open(url, "_blank");
			_window.document.close();
			_window.document.execCommand('SaveAs', true, filename)
			_window.close();
		}
		else {
			var filename = url.substring(url.lastIndexOf("/") + 1).split("?")[0];
			var xhr = new XMLHttpRequest();
			xhr.responseType = 'blob';
			xhr.onload = function() {
				var a = document.createElement('a');
				a.href = window.URL.createObjectURL(xhr.response);
				a.download = filename;
				a.style.display = 'none';
				document.body.appendChild(a);
				a.click();
				delete a;
			};

			xhr.open('GET', url);
			xhr.send();
		}
	}
</script>
</body>
</html>