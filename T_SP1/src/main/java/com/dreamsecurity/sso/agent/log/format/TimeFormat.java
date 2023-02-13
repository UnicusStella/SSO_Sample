package com.dreamsecurity.sso.agent.log.format;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import com.dreamsecurity.sso.agent.log.format.StringFormater;

class TimeFormat implements StringFormater
{
	SimpleDateFormat formater = null;

	public String format(String msg)
	{
		return formater.format(new Date());
	}

	TimeFormat(String format)
	{
		formater = null;
		formater = new SimpleDateFormat(format, Locale.KOREA);
	}
}
