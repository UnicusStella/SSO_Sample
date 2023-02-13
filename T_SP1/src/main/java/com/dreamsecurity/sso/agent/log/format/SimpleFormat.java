package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.StringFormater;

class SimpleFormat implements StringFormater
{
	String str = null;

	public String format(String msg)
	{
		return str;
	}

	SimpleFormat(String str)
	{
		this.str = str;
	}
}
