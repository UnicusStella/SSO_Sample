package com.dreamsecurity.sso.agent.otp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.log.Logger;
import com.dreamsecurity.sso.agent.log.LoggerFactory;
import com.dreamsecurity.sso.agent.token.SSOToken;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.ccd.binary.Base32;

public class GoogleOTP
{
	private static Logger log = LoggerFactory.getInstance().getLogger(GoogleOTP.class);

	public static boolean verify(HttpServletRequest request, String otp)
	{
		boolean result = false;

		if (Util.isEmpty(otp)) {
			return false;
		}

		try {
			HttpSession session = request.getSession(false);

			String token = session.getAttribute("_TOKEN") == null ? "" : (String) session.getAttribute("_TOKEN");

			if (Util.isEmpty(token)) {
				return false;
			}

			SSOToken ssoToken = new SSOToken(token);
			String secret = ssoToken.getProperty("OTP_KEY");

			if (Util.isEmpty(secret)) {
				return false;
			}

			long userCode = Integer.parseInt(otp);
			long currentTime = new Date().getTime();
			long checkTime = currentTime / 30000;

			result = checkCode(secret, userCode, checkTime);
		}
		catch (Exception e) {
			log.error("### GoogleOTP verify Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	public static boolean verify(String secret, String otp)
	{
		boolean result = false;

		try {
			/***
			byte[] secretKey = Hex.decode(secret);

			Base32 base32 = new Base32();
			byte[] encKey = base32.encode(secretKey);
			String strEncKey = new String(encKey);
			***/

			long userCode = Integer.parseInt(otp);
			long currentTime = new Date().getTime();
			long checkTime = currentTime / 30000;

			result = checkCode(secret, userCode, checkTime);
		}
		catch (Exception e) {
			log.error("### GoogleOTP verify Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return result;
	}

	private static boolean checkCode(String secret, long code, long t) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Base32 codec = new Base32();
		byte[] decodedKey = codec.decode(secret);

		// Window is used to check codes generated in the near past.
		// You can use this value to tune how far you're willing to go.
		int window = 0; // 0: 30 sec

		for (int i = -window; i <= window; ++i) {
			long hash = verifyCode(decodedKey, t + i);

			if (hash == code) {
				return true;
			}
		}

		// The validation code is invalid.
		return false;
	}

	private static int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException
	{
		byte[] data = new byte[8];
		long value = t;

		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");

		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);

		int offset = hash[20 - 1] & 0xF;

		// We're using a long because Java hasn't got unsigned int.
		long truncatedHash = 0;

		for (int i = 0; i < 4; ++i) {
			truncatedHash <<= 8;
			// We are dealing with signed bytes:
			// we just keep the first byte.
			truncatedHash |= (hash[offset + i] & 0xFF);
		}

		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		return (int) truncatedHash;
	}

	public static String createSecretKey(int size)
	{
		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			Base32 base32 = new Base32();
			byte[] encKey = base32.encode(crypto.createRandomByte(size));

			return new String(encKey);
		}
		catch (Exception e) {
			log.error("### GoogleOTP createSecretKey Exception: " + e.getMessage());
			e.printStackTrace();
		}

		return "";
	}
}