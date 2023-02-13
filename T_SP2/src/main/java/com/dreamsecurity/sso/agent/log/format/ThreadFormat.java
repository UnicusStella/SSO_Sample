package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.StringFormater;

class ThreadFormat implements StringFormater
{
	public String format(String msg)
	{
		return Thread.currentThread().getName();
	}

	ThreadFormat()
	{
	}
}
