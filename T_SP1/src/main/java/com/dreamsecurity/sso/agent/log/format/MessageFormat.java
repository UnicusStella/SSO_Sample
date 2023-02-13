package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.StringFormater;

class MessageFormat implements StringFormater
{
	String message = null;

	public String format(String msg)
	{
		return msg;
	}

	public MessageFormat()
	{
	}

}