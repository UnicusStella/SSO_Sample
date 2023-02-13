package com.dreamsecurity.sso.server.exception;

public class SSOException extends Exception
{
	private static final long serialVersionUID = 3566499114899357695L;
	protected int code = 9999;
	protected String detail;

	public SSOException()
	{
		super();
	}

	public SSOException(String msg)
	{
		super(msg);
	}

	public SSOException(Throwable _e)
	{
		super(_e);
	}

	public SSOException(String msg, Throwable _e)
	{
		super(msg, _e);
	}

	public SSOException(int code, String msg)
	{
		super(msg);
		this.code = code;
	}

	public SSOException(int code, String msg, String detail)
	{
		super(msg);
		this.code = code;
		this.detail = detail;
	}

	public SSOException(int code, Throwable _e)
	{
		super(_e);
		this.code = code;
	}

	public SSOException(int code, String msg, Throwable _e)
	{
		super(msg, _e);
		this.code = code;
	}

	public int getErrorCode()
	{
		return code;
	}

	public String getDetailMessage()
	{
		return detail;
	}
}