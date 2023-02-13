package com.dreamsecurity.sso.server.api.admin.vo;

public class AdminVO
{
	private String id;
	private String name;
	private String type;
	private String typeText;
	private String ip;
	private String email;
	private String menuCode;
	private String loginIp;
	private String loginBr;
	private String loginTime;
	private String accessTime;

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

	public String getType()
	{
		return type;
	}

	public void setType(String type)
	{
		this.type = type;

		if (type != null && "S".equals(type)) {
			this.typeText = "최고관리자";
		}
		else if (type != null && "N".equals(type)) {
			this.typeText = "모니터링관리자";
		}
		else {
			this.typeText = "";
		}
	}

	public String getTypeText()
	{
		return typeText;
	}

	public String getIp()
	{
		return ip;
	}

	public void setIp(String ip)
	{
		this.ip = ip;
	}

	public String getEmail()
	{
		return email;
	}

	public void setEmail(String email)
	{
		this.email = email;
	}

	public String getMenuCode()
	{
		return menuCode;
	}

	public void setMenuCode(String menuCode)
	{
		this.menuCode = menuCode;
	}

	public String getLoginIp()
	{
		return loginIp;
	}

	public void setLoginIp(String loginIp)
	{
		this.loginIp = loginIp == null ? "" : loginIp;
	}

	public String getLoginBr()
	{
		return loginBr;
	}

	public void setLoginBr(String loginBr)
	{
		this.loginBr = loginBr == null ? "" : loginBr;
	}

	public String getLoginTime()
	{
		return loginTime;
	}

	public void setLoginTime(String loginTime)
	{
		this.loginTime = loginTime == null ? "" : loginTime;
	}

	public String getAccessTime()
	{
		return accessTime;
	}

	public void setAccessTime(String accessTime)
	{
		this.accessTime = accessTime == null ? "" : accessTime;
	}
}