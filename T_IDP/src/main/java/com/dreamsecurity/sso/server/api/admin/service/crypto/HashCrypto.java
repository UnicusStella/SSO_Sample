package com.dreamsecurity.sso.server.api.admin.service.crypto;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiException;
import com.dreamsecurity.sso.server.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.server.util.Util;

public class HashCrypto
{
	private static Logger log = LoggerFactory.getLogger(HashCrypto.class);

	public static final int _PLAIN = 0;
	public static final int _HEX = 1;
	public static final int _BASE64 = 2;

	public static final String _SHA256 = "SHA256";

	private HashCrypto()
	{
	}

	private static class hcSingleton
	{
		private static final HashCrypto instance = new HashCrypto();
	}

	public static HashCrypto getInstance()
	{
		return hcSingleton.instance;
	}

	public String getHash(String src, String hashAlgo, int charCode)
	{
		try {
			byte[] hasedB = CryptoApiFactory.getCryptoApi().digest(src.getBytes("UTF-8"), hashAlgo);
			String result = "";

			switch (charCode) {
			case _HEX:
				result = byteToHex(hasedB);
				break;
			case _BASE64:
				result = Util.encode64(hasedB);
				break;
			}

			return result;
		}
		catch (Exception e) {
			log.error("### getHash(3) Exception: {}", e.toString());
		}

		return null;
	}

	public String getHash(String src, String salt, String hashAlgo, int charCode)
	{
		try {
			byte[] hashedSalt = CryptoApiFactory.getCryptoApi().digest(salt.getBytes("UTF-8"), hashAlgo);
			String newSrc = src + new String(hashedSalt);

			byte[] hasedB = CryptoApiFactory.getCryptoApi().digest(newSrc.getBytes("UTF-8"), hashAlgo);
			String result = "";

			switch (charCode) {
			case _HEX:
				result = byteToHex(hasedB);
				break;
			case _BASE64:
				result = Util.encode64(hasedB);
				break;
			}

			return result;
		}
		catch (Exception e) {
			log.error("### getHashWithSalt(4) Exception: {}", e.toString());
		}

		return null;
	}

	public String getHashWithSalt(String src, String salt)
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			int charCode = config.getIntegerProperty("pwd.char.code", _HEX);
			String hashAlgo = config.getStringProperty("pwd.hash.algo", _SHA256);

			if (charCode == _PLAIN)
				return src;

			byte[] hashedSalt = CryptoApiFactory.getCryptoApi().digest(salt.getBytes("UTF-8"), hashAlgo);
			String newSrc = src + new String(hashedSalt);

			byte[] hasedB = CryptoApiFactory.getCryptoApi().digest(newSrc.getBytes("UTF-8"), hashAlgo);
			String result = "";

			switch (charCode) {
			case _HEX:
				result = byteToHex(hasedB);
				break;
			case _BASE64:
				result = Util.encode64(hasedB);
				break;
			}

			return result;
		}
		catch (Exception e) {
			log.error("### getHashWithSalt(2) Exception: {}", e.toString());
		}

		return null;
	}

	public String getSha256Base64(String src)
	{
		try {
			byte[] hasedB = CryptoApiFactory.getCryptoApi().digest(src.getBytes("UTF-8"), _SHA256);
			return Util.encode64(hasedB);
		}
		catch (Exception e) {
			log.error("### getSha256Base64() Exception: {}", e.toString());
		}

		return null;
	}

	public String getSha256Base64(String src, String salt)
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();

			byte[] hashedSalt = crypto.digest(Hex.decode(salt), _SHA256);
			String newSrc = src + new String(hashedSalt);

			byte[] hasedB = crypto.digest(newSrc.getBytes("UTF-8"), _SHA256);
			return Util.encode64(hasedB);
		}
		catch (Exception e) {
			log.error("### getSha256Base64() Exception: {}", e.toString());
		}

		return null;
	}

	public String getSha256Hex(String src)
	{
		try {
			byte[] hasedB = CryptoApiFactory.getCryptoApi().digest(src.getBytes("UTF-8"), _SHA256);
			return byteToHex(hasedB);
		}
		catch (Exception e) {
			log.error("### getSha256Hex() Exception: {}", e.toString());
		}

		return null;
	}

	public String getSha256Hex(String src, String salt)
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();
			
			byte[] hashedSalt = crypto.digest(Hex.decode(salt), _SHA256);
			String newSrc = src + new String(hashedSalt);

			byte[] hasedB = crypto.digest(newSrc.getBytes("UTF-8"), _SHA256);
			return byteToHex(hasedB);
		}
		catch (Exception e) {
			log.error("### getSha256Hex() Exception: {}", e.toString());
		}

		return null;
	}

	public String generateSalt() throws CryptoApiException
	{
		byte[] salt = CryptoApiFactory.getCryptoApi().getRandom(16, "SHA256DRBG");
		return byteToHex(salt);
	}

	public String byteToHex(byte[] srcB)
	{
		if (srcB == null || srcB.length == 0)
			return null;

		StringBuffer sb = new StringBuffer(srcB.length * 2);
		String hexNumber;

		for (int x = 0; x < srcB.length; x++) {
			hexNumber = "0" + Integer.toHexString(0xff & srcB[x]);
			sb.append(hexNumber.substring(hexNumber.length() - 2));
		}

		return sb.toString();
	}
}