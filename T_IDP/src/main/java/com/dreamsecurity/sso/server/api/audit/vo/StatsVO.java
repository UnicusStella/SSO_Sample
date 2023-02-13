package com.dreamsecurity.sso.server.api.audit.vo;

import java.io.Serializable;

public class StatsVO implements Serializable
{
	private static final long serialVersionUID = -1288684548935835654L;

	private String xvalue;
	private String lcount;
	private String ccount;
	private String ocount;

	public String getXvalue()
	{
		return xvalue;
	}

	public void setXvalue(String xvalue)
	{
		if (xvalue.length() > 1 && xvalue.substring(0, 1).equals("0")) {
			this.xvalue = xvalue.substring(1);
		}
		else {
			this.xvalue = xvalue;
		}
	}

	public String getLcount()
	{
		return lcount;
	}

	public void setLcount(String lcount)
	{
		this.lcount = lcount;
	}

	public String getCcount()
	{
		return ccount;
	}

	public void setCcount(String ccount)
	{
		this.ccount = ccount;
	}

	public String getOcount()
	{
		return ocount;
	}

	public void setOcount(String ocount)
	{
		this.ocount = ocount;
	}

}