package com.dreamsecurity.sso.server.api.audit.vo;

public class AuditListVO
{
	private String index;
	private String logDate;
	private String logTime;
	private String logDatetime;
	private String caseUser;
	private String caseType;
	private String caseResult;
	private String caseData;

	public String getIndex()
	{
		return index;
	}

	public void setIndex(String index)
	{
		this.index = index;
	}

	public String getLogDate()
	{
		return logDate;
	}

	public void setLogDate(String logDate)
	{
		if (logDate != null && logDate.length() == 8) {
			String temp = logDate.substring(0, 4) + "-";
			temp += logDate.substring(4, 6) + "-";
			temp += logDate.substring(6);
			this.logDate = temp;
		}
		else {
			this.logDate = logDate;
		}

		this.logDatetime = this.logDate + "&nbsp;&nbsp;" + this.logTime;
	}

	public String getLogTime()
	{
		return logTime;
	}

	public void setLogTime(String logTime)
	{
		if (logTime != null && logTime.length() == 6) {
			String temp = logTime.substring(0, 2) + ":";
			temp += logTime.substring(2, 4) + ":";
			temp += logTime.substring(4);
			this.logTime = temp;
		}
		else {
			this.logTime = logTime;
		}

		this.logDatetime = this.logDate + "&nbsp;&nbsp;" + this.logTime;
	}

	public String getCaseUser()
	{
		return caseUser;
	}

	public void setCaseUser(String caseUser)
	{
		this.caseUser = caseUser;
	}

	public String getCaseType()
	{
		return caseType;
	}

	public void setCaseType(String caseType)
	{
		if (caseType != null && caseType.length() == 2) {
			if ("AA".equals(caseType))
				this.caseType = "감사 기능 시작/종료";
			else if ("AB".equals(caseType))
				this.caseType = "관리자 로그인 요청";
			else if ("AC".equals(caseType))
				this.caseType = "암호모듈 자가시험";
			else if ("AD".equals(caseType))
				this.caseType = "SSO모듈 무결성 검증";
			else if ("AE".equals(caseType))
				this.caseType = "감사정보 용량 임계치 초과";
			else if ("AF".equals(caseType))
				this.caseType = "감사정보 설정 변경";
			else if ("AG".equals(caseType))
				this.caseType = "사용자 로그인 요청";
			else if ("AH".equals(caseType))
				this.caseType = "사용자 연계 요청";
			else if ("AI".equals(caseType))
				this.caseType = "사용자 비밀번호 변경";
			else if ("AJ".equals(caseType))
				this.caseType = "중복 로그인 방지";
			else if ("AK".equals(caseType))
				this.caseType = "안전한 경로/채널 사용";
			else if ("AL".equals(caseType))
				this.caseType = "세션 비활동 시간 경과";
			else if ("AM".equals(caseType))
				this.caseType = "암호키 생성";
			else if ("AN".equals(caseType))
				this.caseType = "메일서버 설정 변경";
			else if ("AO".equals(caseType))
				this.caseType = "메일정보 설정 변경";
			else if ("BE".equals(caseType))
				this.caseType = "사용자 정보 변경";
			else if ("AP".equals(caseType))
				this.caseType = "사용자 정책 변경";
			else if ("AQ".equals(caseType))
				this.caseType = "사용자 잠김 해제";
			else if ("AR".equals(caseType))
				this.caseType = "관리자 정보 변경";
			else if ("AS".equals(caseType))
				this.caseType = "관리자 정책 변경";
			else if ("AT".equals(caseType))
				this.caseType = "관리자 접속 IP 변경";
			else if ("AU".equals(caseType))
				this.caseType = "관리자 비밀번호 변경";
			else if ("AV".equals(caseType))
				this.caseType = "암호키 분배";
			else if ("AW".equals(caseType))
				this.caseType = "암호키 파기";
			else if ("AX".equals(caseType))
				this.caseType = "암호 연산";
			else if ("AY".equals(caseType))
				this.caseType = "메일 발송";
			else if ("AZ".equals(caseType))
				this.caseType = "비밀정보 파기";
			else if ("BA".equals(caseType))
				this.caseType = "인증토큰 생성";
			else if ("BB".equals(caseType))
				this.caseType = "SSO프로세스 확인";
			else if ("BC".equals(caseType))
				this.caseType = "관리자 로그아웃";
			else if ("BD".equals(caseType))
				this.caseType = "사용자 로그아웃";
			else if ("BF".equals(caseType))
				this.caseType = "클라이언트 정보 변경";
			else if ("BG".equals(caseType))
				this.caseType = "Scope 정보 변경";
			else if ("BH".equals(caseType))
				this.caseType = "사용자 2차 인증";
			else
				this.caseType = caseType;
		}
		else {
			this.caseType = caseType;
		}
	}

	public String getCaseResult()
	{
		return caseResult;
	}

	public void setCaseResult(String caseResult)
	{
		if (caseResult != null && caseResult.length() == 1) {
			if ("0".equals(caseResult))
				this.caseResult = "성공";
			else
				this.caseResult = "실패";
		}
		else {
			this.caseResult = caseResult;
		}
	}

	public String getCaseData()
	{
		return caseData;
	}

	public void setCaseData(String caseData)
	{
		this.caseData = caseData;
	}
}