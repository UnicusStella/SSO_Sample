package com.dreamsecurity.sso.agent.crypto;

public class CryptoApiException extends Exception
{
	private static final long serialVersionUID = -3313070995623928745L;
	private int code = 4000;

	public CryptoApiException()
	{
		super();
	}

	public CryptoApiException(String msg)
	{
		super(msg);
	}

	public CryptoApiException(Throwable _e)
	{
		super(_e);
	}

	public CryptoApiException(String msg, Throwable _e)
	{
		super(msg, _e);
	}

	public CryptoApiException(int code, String msg)
	{
		super(msg);
		this.code = code;
	}

	public CryptoApiException(int code, Throwable _e)
	{
		super(_e);
		this.code = code;
	}

	public CryptoApiException(int code, String msg, Throwable _e)
	{
		super(msg, _e);
		this.code = code;
	}

	public int getCode()
	{
		return code;
	}
}