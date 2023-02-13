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

	<script src="js/highcharts.js" type="text/javascript"></script>

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

		<div class="page-breadcrumb">
			HOME / 감사 정보 / 접속 정보 통계
		</div>
		<div class="page-header">
			<h4 class="title">접속 정보 통계</h4>
		</div>
		<div class="content-box">
			<div class="content-top pb-30">
				<div class="float-left">
					<button class="subtitle-btn" type="button"></button>
					<span class="subtitle-text" id="subtitle"></span>
				</div>
				<div class="float-right">
					<select class="search-base width-120" id="sel-type">
					    <option value="1" selected="selected">일간 시간대별</option>
					    <option value="2">월간 일별</option>
					    <option value="3">연간 월별</option>
					</select>
					<input class="date-input ml-10" type="text" id="sel-date" title="조회 시작일"/>
					<button class="btn ml-15" type="button" id="searchBtn">조 회</button>
				</div>
			</div>
			<div class="content-body">
				<div id="stats_chart" style="width:100%; height:100%;"></div>
			</div>
		</div>
	</div>

<script type="text/javascript">
	var xvalArr = new Array(24);
	var loginCntArr = new Array(24);
	var connectCntArr = new Array(24);
	var logoutCntArr = new Array(24);

	$(document).ready(function(){
		checkAdmin();

		$("#sel-date").val(getCurrentDate());
		search()
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
		$("#sel-date").datepicker({
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

	$("#sel-date").keydown(function(e) {
		if (e.keyCode == 8) {
			return true;
		} else if (((e.keyCode > 31) && (e.keyCode < 48)) || (e.keyCode > 57)) {
			return false;
		}
		var size = $("#sel-date").val();
		if (size.length == 4)
			size += "-";
		if (size.length == 7)
			size += "-";
		if (size.length == 10)
			return false;
		$("#sel-date").val(size);
	});

	$("#searchBtn").click(function(){
		search();
	});

	function search()
	{
		var stype = $("#sel-type option:selected").val();

		format = /^(19|20)\d{2}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[0-1])$/;
		if (!format.test($("#sel-date").val())) {
			alert(" 조회 일자를 정확하게 입력하세요.");
			$("#sel-date").focus();
			return;
		}

		var sdate;

		if (stype == "1") {
			xvalArr = new Array(24);
			loginCntArr = new Array(24);
			connectCntArr = new Array(24);
			logoutCntArr = new Array(24);
			sdate = $("#sel-date").val();
		}
		else if (stype == "2") {
			xvalArr = new Array(31);
			loginCntArr = new Array(31);
			connectCntArr = new Array(31);
			logoutCntArr = new Array(31);
			sdate = $("#sel-date").val().substring(0,7);
		}
		else if (stype == "3") {
			xvalArr = new Array(12);
			loginCntArr = new Array(12);
			connectCntArr = new Array(12);
			logoutCntArr = new Array(12);
			sdate = $("#sel-date").val().substring(0,4);
		}

		sdate = sdate.replace(/-/g,'');

		$.ajax({
			type: "POST",
			url: "sub/getAccessStats.jsp",
			data: {stype:stype, sdate:sdate},
			dataType: "JSON",
			async: false,
			success: function(data) {
				if (data != null) {
					for (var i = 0; i < data.records; i++) {
						xvalArr[i] = data.rows[i].xvalue;
						loginCntArr[i] = parseInt(data.rows[i].lcount);
						connectCntArr[i] = parseInt(data.rows[i].ccount);
						logoutCntArr[i] = parseInt(data.rows[i].ocount);
					}
					showChart(stype);
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

	function getCurrentDate()
	{	// YYYY-MM-DD
		var now = new Date();      
		var nowDate = now.getFullYear() + "-";
		nowDate += now.getMonth()+1 < 10 ? "0" + (now.getMonth()+1) : now.getMonth()+1;
		nowDate += "-";
		nowDate += now.getDate() < 10 ? "0" + now.getDate() : now.getDate();
		return nowDate;
	}

	function showChart(stype)
	{
		var t_title, t_xtitle, per;

		if (stype == "1") {
			t_title = '일간 시간대별 접속 현황 (' + $("#sel-date").val() + ')';
			t_xtitle = '시간대별 (시)';
			per = '시';
		}
		else if (stype == "2") {
			t_title = '월간 일별 접속 현황 (' + $("#sel-date").val().substring(0,7) + ')';
			t_xtitle = '일별 (일)';
			per = '일';
		}
		else if (stype == "3") {
			t_title = '연간 월별 접속 현황 (' + $("#sel-date").val().substring(0,4) + ')';
			t_xtitle = '월별 (월)';
			per = '월';
		}

		$("#subtitle").text(t_title);

		var chart = {
				type: 'column'
				};
		var title = {
				text: ''
				};
		var subtitle = {
				text: ''
				};
		var xAxis = {
				categories: xvalArr,
				crosshair: true,
				title: { text: t_xtitle,
						style: { fontSize: '14px' }
					}
				};
		var yAxis = {
				min: 0,
				title: { text: '접속수 (회)',
						style: { fontSize: '14px' }
					}    
				};
		var tooltip = {
				headerFormat: '<table style="width:120px;"><tr><td colspan="2" style="text-align:center;"><span style="font-size:12px; font-weight:600">{point.key} ' + per + '</span></td>',
				pointFormat: '<tr><td style="width:53px; color:{series.color};padding:0">{series.name}: </td>' +
					'<td style="padding:0; text-align:right;"><b>{point.y:.0f}</b></td></tr>',
				footerFormat: '</table>',
				shared: true,
				useHTML: true
				};
		var plotOptions = {
				column: {
					pointPadding: 0.2,
					borderWidth: 0
					}
				};
		var credits = {
				enabled: false
				};
		var series= [{
				name: 'login',
				data: loginCntArr,
				color: '#92cd26'
				},
				{
				name: 'connect',
				data: connectCntArr,
				color: '#2692cd'
				},
				{
				name: 'logout',
				data: logoutCntArr,
				color: '#cd2692'
				}];     

		var json = {};
		json.chart = chart;
		json.title = title;
		json.subtitle = subtitle;
		json.tooltip = tooltip;
		json.xAxis = xAxis;
		json.yAxis = yAxis;
		json.series = series;
		json.plotOptions = plotOptions;
		json.credits = credits;

		Highcharts.chart('stats_chart', json);
	}

</script>
</body>
</html>