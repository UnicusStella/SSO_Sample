package com.dreamsecurity.sso.server.token;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.SimpleTimeZone;

import com.dreamsecurity.jcaos.util.encoders.Hex;
import com.dreamsecurity.sso.lib.xsc.utils.Base64;
import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.crypto.CryptoApi;
import com.dreamsecurity.sso.server.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.crypto.SSOSecretKey;
import com.dreamsecurity.sso.server.exception.SSOException;
import com.dreamsecurity.sso.server.util.Util;

public class LtpaToken
{
	private static final byte PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH = 4;
	private static final int PUBLIC_MODULUS_LENGTH = 129;
	private static final byte PUBLIC_EXPONENT_LENGTH = 3;
	private static final byte PRIVATE_P_Q_LENGTH = 65;

	public static String generateLtpa2Token(String user) throws SSOException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			String realm = config.getString("ltpa.realm", "");
			int expire = config.getInt("ltpa.expire", 120);

			GregorianCalendar expireDate = new GregorianCalendar(new SimpleTimeZone(0, "UTC"));
			expireDate.add(Calendar.MINUTE, expire);
			long expireTime = expireDate.getTimeInMillis();

			//user: CN=project1,O=Domino
			//userinfo: expire:1617613966666$u:user\:defaultWIMFileBasedRealm/CN=project1,O=Domino

			StringBuffer userinfo = new StringBuffer();
			userinfo.append("expire:").append(expireTime).append("$");
			userinfo.append("u:user\\:").append(realm).append("/").append(user);

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			byte[] hashBytes = crypto.hash(userinfo.toString().getBytes("UTF-8"), "SHA-1");

			PrivateKey privateKey = decryptPrivateKey();
			String signData = crypto.signature(privateKey, hashBytes, "SHA1withRSA");

			StringBuffer token = new StringBuffer();
			token.append(userinfo.toString()).append("%");
			token.append(expireTime).append("%");
			token.append(signData);

			byte[] secret = decryptSharedKey();
			byte[] key = new byte[16];
			System.arraycopy(secret, 0, key, 0, 16);

			return crypto.encrypt(key, key, token.toString(), "AES", "AES/CBC/PKCS5Padding");
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException(e.getMessage());
		}
	}

	public static String parseLtpa2Token(String input) throws SSOException
	{
		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			byte[] secret = decryptSharedKey();
			byte[] key = new byte[16];
			System.arraycopy(secret, 0, key, 0, 16);

			byte[] decryptBytes = crypto.decrypt(key, key, input, "AES", "AES/CBC/PKCS5Padding");
			String decryptData = new String(decryptBytes, "UTF-8");

			String[] parts = decryptData.split("\\%");
			if (parts.length != 3) {
				return "";
			}

			byte[] hashBytes = crypto.hash(parts[0].getBytes("UTF-8"), "SHA-1");

			PublicKey publicKey = decodePublicKey();
			crypto.verify(publicKey, parts[2], hashBytes, "SHA1withRSA");

			return parts[0];
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException(e.getMessage());
		}
	}

	private static byte[] decryptKey(String encryptedKey, String password) throws SSOException
	{
		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			byte[] pwBytes = crypto.decryptSym(password);
			byte[] hashKey = crypto.hash(pwBytes, "SHA-1");
			byte[] desKey = Arrays.copyOfRange(hashKey, 0, 24);
			byte[] result = crypto.decrypt(desKey, encryptedKey, "DESede", "DESede/ECB/PKCS5Padding");

			return result;
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException(e.getMessage());
		}
	}

	private static byte[] decryptSharedKey() throws SSOException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			String pwd = config.getString("ltpa.key", "");
			String encKey = config.getString("ltpa.secret", "");

			return decryptKey(encKey, pwd);
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException(e.getMessage());
		}
	}

	private static PrivateKey decryptPrivateKey() throws SSOException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			String pwd = config.getString("ltpa.key", "");
			String encKey = config.getString("ltpa.private", "");

			byte[] decKey = decryptKey(encKey, pwd);
			//String aa = SSOCryptoApi.encode64(decKey);
			//aa.toString();

			int privateExponentLength = (new BigInteger(Arrays.copyOfRange(decKey, 0, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH))).intValue();
			//int privateExponentLength = (new BigInteger(Arrays.copyOfRange(decKey, 0, 4))).intValue(); // 128
			BigInteger privateExponent = new BigInteger(Arrays.copyOfRange(decKey, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH,
					PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength));
			//BigInteger privateExponent = new BigInteger(Arrays.copyOfRange(decKey, 4,	4 + 128));
			BigInteger p = new BigInteger(Arrays.copyOfRange(decKey, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH,
					PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH + PRIVATE_P_Q_LENGTH));
			//BigInteger p = new BigInteger(Arrays.copyOfRange(decKey, 4 + 128 + 3, 4 + 128 + 3 + 65));
			BigInteger q = new BigInteger(Arrays.copyOfRange(decKey, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH + PRIVATE_P_Q_LENGTH,
					PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH + PRIVATE_P_Q_LENGTH + PRIVATE_P_Q_LENGTH));
			//BigInteger q = new BigInteger(Arrays.copyOfRange(decKey, 4 + 128 + 3 + 65, 4 + 128 + 3 + 65 + 65));
			BigInteger modulus = p.multiply(q);

			RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			//PrivateKey kk = kf.generatePrivate(privKeySpec);
			//String bb = SSOCryptoApi.encode64(kk.getEncoded());
			//bb.toString();
			return kf.generatePrivate(privKeySpec);
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException(e.getMessage());
		}
	}

	private static PublicKey decodePublicKey() throws SSOException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			String encKey = config.getString("ltpa.public", "");

			byte[] decKey = Base64.decode(encKey);

			if (decKey.length != PUBLIC_MODULUS_LENGTH + PUBLIC_EXPONENT_LENGTH) {
				throw new SSOException("Invalid encrypted PublicKey");
			}

			BigInteger modulus = new BigInteger(Arrays.copyOfRange(decKey, 0, PUBLIC_MODULUS_LENGTH));
			BigInteger exponent = new BigInteger(Arrays.copyOfRange(decKey, PUBLIC_MODULUS_LENGTH, PUBLIC_MODULUS_LENGTH + PUBLIC_EXPONENT_LENGTH));

			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(pubKeySpec);
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException(e.getMessage());
		}
	}

	public static String generateSiluetToken(String input) throws SSOException
	{
		try {
			SSOConfig config = SSOConfig.getInstance();
			String pubKey = config.getString("ltpa.public", "");
			int expire = config.getInt("ltpa.expire", 720);

			// Private Key javascript encode
			//String aa = new String(Hex.encode(Base64.decode("MIICWgIBAAKBgFog8p03gFcFFrj4n0gDtznzDpJ9BDvBOj/tIryF/WE1OCDI+MdNGfYsvIgCa3ZeH/kKbwAZRhoPEYTus4a0ygunSr/JuMK9HOHh/QRzzVrCH+WgQ8cGprqOz6pV1xK0BYdhfROcCSTAdpU9owpNO/7X6iwXseEq3t42jDJ6FFllAgMBAAECgYAiDg7+HqmMt+yFCdRNhrHl4JQh/8DovzM+UmDssQgzgcNqh+WQkO59WRwHnDp0qE4WcL3OYL5fPFBXVUZaYNdyqvZxOXNC2NqdR/su+URJno0AaikIKw+9ojbrESRh2DT8MV63LUQ5lFLVhQwXaS0smWyaPDvW9xzyL521Z1AjRQJBAJxE4fEf8Jut8fDO6oNLkZun8Gkd/NT6xtvL+BQaWAqV6FsTOadgym8Qa8f6VtV5x1fWmnHUcwiIJzoMeIDd3GsCQQCTphqNTN1LYVTAjj7Hi4vGc/+vpzKTbcWiMvq8ZJuu4CVvpR0PU1Wrp+nMpaA8gWkAuHFlIKqh87Riu4gXpxVvAkBaEn4lLOLT6QQuaCXWPeWU0c0J2eYUoOOkZ0H73F9o4pVGgaNWrbyhHdbyMoKAk6vqHmFxQSJ5BXmOxQdkR/03AkANL699YRj+a3HjRJDsx1SzY5a5PEhzDEGzS7RC8QVKZ/BP+UIQJVQoYXWq9jvKS5ByJQbTjkhO8HHyw2bTHfP3AkB9f6QiFZv59XmG3BQSlEs7brWTWojjN3emfvT0d0T7gEx5bw05wAqp/AdpPCo5j6aDhCwhPw1bHx+AmlcDNETP")));
			//System.out.println(aa);

			//GregorianCalendar expireDate = new GregorianCalendar(new SimpleTimeZone(0, "UTC"));
			//expireDate.add(Calendar.MINUTE, expire);
			//long expireTime = expireDate.getTimeInMillis();
			long expireTime = System.currentTimeMillis();
			expireTime += expire * 60 * 1000;

			StringBuffer userinfo = new StringBuffer();
			userinfo.append(expireTime).append("$").append(input);

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			CryptoApi cryptoApi = CryptoApiFactory.getCryptoApi();

			SSOSecretKey secKey = crypto.generateSecretKey();
			byte[] encUserinfo = cryptoApi.encrypt(secKey.getKey(), secKey.getIv(), userinfo.toString().getBytes("UTF-8"), "SEED", "SEED/CBC/PKCS5Padding");
			Util.zeroize(userinfo);

			// PEM to PublicKey
			X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decode(pubKey));
			KeyFactory kf = KeyFactory.getInstance("RSA");

			byte[] encKey = cryptoApi.encryptPublicKey(kf.generatePublic(spec), Hex.encode(secKey.getKeyIv()), "RSA/None/PKCS1Padding");
			secKey.finalize();

			return Base64.encode(Util.concatBytes(encKey, encUserinfo));
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new SSOException(e.getMessage());
		}
	}

}