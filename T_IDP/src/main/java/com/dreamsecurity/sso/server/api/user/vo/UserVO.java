package com.dreamsecurity.sso.server.api.user.vo;

public class UserVO
{
	private String index;
	private String id;
	private String name;
	private String status;
	private String statusNm;
	private String logintime;
	private String loginip;
	private String loginbr;

	public String getIndex()
	{
		return index;
	}

	public void setIndex(String index)
	{
		this.index = index;
	}

	public String getId()
	{
		return id;
	}

	public void setId(String id)
	{
		this.id = id;
	}

	public String getName()
	{
		return name;
	}

	public void setName(String name)
	{
		this.name = name;
	}

	public String getStatus()
	{
		return status;
	}

	public void setStatus(String status)
	{
		this.status = status;
		if (status != null && "C".equals(status))
			this.statusNm = "정상";
		else if (status != null && "D".equals(status))
			this.statusNm = "잠김";
		else if (status != null && "E".equals(status))
			this.statusNm = "퇴직";
		else
			this.statusNm = "";
	}

	public String getStatusNm()
	{
		return statusNm;
	}

	public String getLogintime()
	{
		return logintime;
	}

	public void setLogintime(String logintime)
	{
		if (logintime != null && logintime.length() >= 14) {
			String temp = logintime.substring(0, 4) + "-";
			temp += logintime.substring(4, 6) + "-";
			temp += logintime.substring(6, 8) + "&nbsp;&nbsp;";
			temp += logintime.substring(8, 10) + ":";
			temp += logintime.substring(10, 12) + ":";
			temp += logintime.substring(12, 14);

			this.logintime = temp;
		}
		else {
			this.logintime = logintime;
		}
	}

	public String getLoginip()
	{
		return loginip;
	}

	public void setLoginip(String loginip)
	{
		this.loginip = loginip;
	}

	public String getLoginbr()
	{
		return loginbr;
	}

	public void setLoginbr(String loginbr)
	{
		if (loginbr != null && loginbr.length() == 2) {
			if ("IE".equals(loginbr))
				this.loginbr = "I.Explorer";
			else if ("EG".equals(loginbr))
				this.loginbr = "Edge";
			else if ("CR".equals(loginbr))
				this.loginbr = "Chrome";
			else if ("OP".equals(loginbr))
				this.loginbr = "Opera";
			else if ("FF".equals(loginbr))
				this.loginbr = "Firefox";
			else if ("SF".equals(loginbr))
				this.loginbr = "Safari";
			else
				this.loginbr = "None";
		}
		else {
			this.loginbr = loginbr;
		}
	}
}