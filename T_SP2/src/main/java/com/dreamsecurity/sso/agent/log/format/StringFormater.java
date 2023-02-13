package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.Formater;

public interface StringFormater extends Formater
{
	public String format(String msg);
}
