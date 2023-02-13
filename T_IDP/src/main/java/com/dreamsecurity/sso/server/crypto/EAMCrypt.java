package com.dreamsecurity.sso.server.crypto;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.util.ByteUtil;

public class EAMCrypt
{
	private static Logger log = LoggerFactory.getLogger(EAMCrypt.class);

	private static EAMCrypt instance = null;
	private static CryptoApi crypto = null;

	private String cryptoAlgorithm = "SEED";
	private String cipherAlgorithm = "SEED/ECB/PKCS5Padding";

	private final byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	private EAMCrypt() throws CryptoApiException
	{
		crypto = CryptoApiFactory.getCryptoApi();
	}

	public static EAMCrypt getInstance() throws CryptoApiException
	{
		if (instance == null) {
			synchronized (EAMCrypt.class) {
				if (instance == null) {
					instance = new EAMCrypt();
				}
			}
		}

		return instance;
	}

	public String encrypt(String input) throws CryptoApiException
	{
		String result = "";

		try {
			byte[] encBytes = crypto.encrypt(this.key, input.getBytes("UTF-8"), this.cryptoAlgorithm, this.cipherAlgorithm);

			result = ByteUtil.toHexString(encBytes);
		}
		catch (Exception e) {
			log.error("### EAMCrypt.encrypt() Exception: {}", e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_ENCRYPT, e);
		}

		return result;
	}

	public String decrypt(String input) throws CryptoApiException
	{
		try {
			byte[] encBytes = ByteUtil.toBytes(input);

			byte[] decBytes = crypto.decrypt(this.key, encBytes, this.cryptoAlgorithm, this.cipherAlgorithm);
			
			return new String(decBytes, "UTF-8");
		}
		catch (Exception e) {
			log.error("### EAMCrypt.decrypt() Exception: {}", e.toString());
			throw new CryptoApiException(MStatus.CRYPTO_DECRYPT, e);
		}
	}
}