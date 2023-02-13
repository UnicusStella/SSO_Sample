package com.dreamsecurity.sso.server.api.admin.vo;

public class UserAccessInfo
{
	private String index;
	private String logDate;
	private String logTime;
	private String userId;
	private String userName;
	private String accessIp;
	private String accessBr;
	private String accessSp;
	private String accessType;
	private String accessRslt;

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
	}

	public String getUserId()
	{
		return userId;
	}

	public void setUserId(String userId)
	{
		this.userId = userId;
	}

	public String getUserName()
	{
		return userName;
	}

	public void setUserName(String userName)
	{
		this.userName = userName;
	}

	public String getAccessIp()
	{
		return accessIp;
	}

	public void setAccessIp(String accessIp)
	{
		this.accessIp = accessIp;
	}

	public String getAccessBr()
	{
		return accessBr;
	}

	public void setAccessBr(String accessBr)
	{
		if (accessBr != null && accessBr.length() == 2) {
			if ("IE".equals(accessBr))
				this.accessBr = "I.Explorer";
			else if ("EG".equals(accessBr))
				this.accessBr = "Edge";
			else if ("CR".equals(accessBr))
				this.accessBr = "Chrome";
			else if ("OP".equals(accessBr))
				this.accessBr = "Opera";
			else if ("FF".equals(accessBr))
				this.accessBr = "Firefox";
			else if ("SF".equals(accessBr))
				this.accessBr = "Safari";
			else if ("CS".equals(accessBr))
				this.accessBr = "CS";
			else
				this.accessBr = "None";
		}
		else {
			this.accessBr = accessBr;
		}
	}

	public String getAccessSp()
	{
		return accessSp;
	}

	public void setAccessSp(String accessSp)
	{
		this.accessSp = accessSp;
	}

	public String getAccessType()
	{
		return accessType;
	}

	public void setAccessType(String accessType)
	{
		if (accessType != null && accessType.length() == 2) {
			if ("01".equals(accessType))
				this.accessType = "ID/PW 로그인";
			else if ("02".equals(accessType))
				this.accessType = "ID 로그인";
			else if ("03".equals(accessType))
				this.accessType = "인증서 로그인";
			else if ("09".equals(accessType))
				this.accessType = "기타 로그인";
			else if ("11".equals(accessType))
				this.accessType = "ID/PW 로그아웃";
			else if ("12".equals(accessType))
				this.accessType = "ID 로그아웃";
			else if ("13".equals(accessType))
				this.accessType = "인증서 로그아웃";
			else if ("19".equals(accessType))
				this.accessType = "기타 로그아웃";
			else if ("98".equals(accessType))
				this.accessType = "2차 로그인";
			else if ("99".equals(accessType))
				this.accessType = "연계 로그인";
			else
				this.accessType = "None";
		}
		else {
			this.accessType = accessType;
		}
	}

	public String getAccessRslt()
	{
		return accessRslt;
	}

	public void setAccessRslt(String accessRslt)
	{
		if (accessRslt != null && accessRslt.length() == 2) {
			if ("00".equals(accessRslt))
				this.accessRslt = "성공";
			else if ("AA".equals(accessRslt))
				this.accessRslt = "아이디 잠김";
			else if ("AB".equals(accessRslt))
				this.accessRslt = "퇴직자 아이디";
			else if ("AC".equals(accessRslt))
				this.accessRslt = "중복 로그인";
			else if ("AD".equals(accessRslt))
				this.accessRslt = "비밀번호 오류";
			else if ("AE".equals(accessRslt))
				this.accessRslt = "아이디 오류";
			else if ("AF".equals(accessRslt))
				this.accessRslt = "DN 오류";
			else
				this.accessRslt = "None";
		}
		else {
			this.accessRslt = accessRslt;
		}
	}
}