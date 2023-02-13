package com.dreamsecurity.sso.server.crypto;

public class SSOSecretKey
{
	private String algorithm;
	private byte[] key = null;
	private byte[] iv = null;
	private byte[] param = null;

	public SSOSecretKey(String algorithm, byte[] key, byte[] iv)
	{
		this.algorithm = algorithm;
		this.key = key;
		this.iv = iv;
		this.param = new byte[key.length + iv.length];
		System.arraycopy(key, 0, param, 0, key.length);
		System.arraycopy(iv, 0, param, key.length, iv.length);
	}

	public SSOSecretKey(String algorithm, byte[] param)
	{
		if (param.length != 32)
			return;

		this.algorithm = algorithm;
		this.key = new byte[16];
		this.iv = new byte[16];
		this.param = param;
		System.arraycopy(param, 0, this.key, 0, this.key.length);
		System.arraycopy(param, this.key.length, this.iv, 0, this.iv.length);
	}

	public String getAlgorithm()
	{
		return algorithm;
	}

	public void setAlgorithm(String algorithm)
	{
		this.algorithm = algorithm;
	}

	public byte[] getKey()
	{
		return key;
	}

	public void setKey(byte[] key)
	{
		this.key = key;
	}

	public byte[] getIv()
	{
		return iv;
	}

	public void setIv(byte[] iv)
	{
		this.iv = iv;
	}

	public byte[] getKeyIv()
	{
		return param;
	}

	public void finalize()
	{
		if (this.key != null) {
			for (int i = 0; i < this.key.length; i++)
				this.key[i] = (byte) 0x00;
			this.key = null;
		}

		if (this.iv != null) {
			for (int j = 0; j < this.iv.length; j++)
				this.iv[j] = (byte) 0x00;
			this.iv = null;
		}

		if (this.param != null) {
			for (int k = 0; k < this.param.length; k++)
				this.param[k] = (byte) 0x00;
			this.param = null;
		}
	}
}