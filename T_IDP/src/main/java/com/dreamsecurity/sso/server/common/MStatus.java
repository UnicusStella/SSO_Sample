package com.dreamsecurity.sso.server.common;

public class MStatus
{
	public static final int SUCCESS = 0;
	public static final int FAIL = -1;

	public static final int READY = -5;

	public static final int ENC_CERT = 0;
	public static final int SIGN_CERT = 1;

	public static final int USER_AUTH_FAIL = 10001;
	public static final int USER_ID_NOT_EXIST = 10001;
	public static final int USER_DN_NOT_EXIST = 10002;
	public static final int USER_PW_NOT_MATCH = 10003;
	public static final int USER_ID_LOCK = 10010;
	public static final int USER_ID_RETIREMENT = 10011;
	public static final int USER_DUP_LOGIN = 10012;
	public static final int CREATE_TOKEN_FAIL = 10019;
	public static final int ETC_AUTH_FAIL = 19000;

	public static final int ADMIN_AUTH_FAIL = 90000;
	public static final int ADMIN_ID_NOT_EXIST = 90001;
	public static final int ADMIN_PW_NOT_MATCH = 90002;
	public static final int ADMIN_IP_FAIL = 90003;
	public static final int ADMIN_ANOTHER_USING = 90004;
	public static final int ADMIN_ID_LOCK = 90005;

	public static final String MSG_USER_ID_NOT_EXIST = "Not Exist User Account";
	public static final String MSG_USER_DN_NOT_EXIST = "Not Exist User DN";
	public static final String MSG_USER_PW_NOT_MATCH = "Mismatch User Password";
	public static final String MSG_USER_ID_LOCK = "Current User Account is Locking";
	public static final String MSG_USER_ID_RETIREMENT = "Current User Account is a retired employee";

	public static final int AUTH_NON_ACTIVE = 2000;
	public static final int AUTH_MESSAGE_DECODE = 2001;
	public static final int AUTH_TOKEN_NULL = 2002;
	public static final int AUTH_SESSION_NOT_EQUALS = 2003;
	public static final int AUTH_SUBJECT_INVALID = 2004;
	public static final int AUTH_SUBJECT_VALUE_INVALID = 2005;
	public static final int AUTH_TOKEN_ENCRYPT = 2006;
	public static final int AUTH_ID_INVALID = 2007;
	public static final int AUTH_ISSUE_TIME_INVALID = 2008;
	public static final int AUTH_REQUEST_DATA_EMPTY = 2009;
	public static final int AUTH_USER_ID_NOT_MATCH = 2010;
	public static final int AUTH_NOT_LOGIN = 2011;
	public static final int AUTH_REQUEST_DATA_INVALID = 2012;
	public static final int AUTH_REQUEST_DECRYPT_FAIL = 2013;
	public static final int AUTH_RELAYSTATE_EMPTY = 2014;
	public static final int AUTH_RELAYSTATE_NOT_MATCH = 2015;

	//public static final int AUTH_SERVER_LOGIN = 2080;
	public static final int AUTH_EXCEPTION = 2099;

	public static final int AUTH_REQ_GENERATE = 2100;
	public static final int AUTH_REQ_SEND = 2101;
	public static final int AUTH_REQ_NULL = 2102;
	public static final int AUTH_REQ_DUPLICATE = 2103;
	public static final int AUTH_REQ_TIMEOUT = 2104;
	public static final int AUTH_REQ_VERIFY = 2105;
	public static final int AUTH_REQ_PASSIVE = 2106;
	public static final int AUTH_REQ_FORCE_AUTHN = 2107;
	public static final int AUTH_REQ_SUBJECT_NULL = 2108;
	public static final int AUTH_REQ_CS_LOGOUT = 2109;
	public static final int AUTH_REQ_PARAMETER = 2110;

	public static final int ASSERT_GET = 2200;
	public static final int ASSERT_TIMEOUT = 2201;
	public static final int ASSERT_VERIFY = 2202;
	public static final int ASSERT_EXCEPTION = 2203;
	public static final int ASSERT_CHALLENGE = 2204;
	public static final int ASSERT_CHALLENGE_NULL = 2205;

	public static final int LOGOUT_REQ_NULL = 2301;
	public static final int LOGOUT_REQ_TIMEOUT = 2302;

	public static final int ERR_INTEGRITY = 3000;
	public static final int ERR_GET_PRIVATEKEY = 3001;
	public static final int ERR_LOAD_PRIVATEKEY = 3002;
	public static final int ERR_BASE64_DECODE = 3003;
	public static final int ERR_GEN_SIGN_XML = 3004;
	public static final int ERR_ZEROIZE = 3005;

	public static final int ERR_PARAMETER = 3100;
	public static final int ERR_DATA_SIZE = 3101;
	public static final int ERR_DATA_TIMEOUT = 3102;
	public static final int ERR_DATA_FORMAT = 3103;
	public static final int ERR_DATA_PARSE = 3104;
	public static final int ERR_DATA_VERIFY = 3105;

	public static final int CRYPTO_INSTANCE = 4000;
	public static final int CRYPTO_SELF_TEST = 4001;
	public static final int CRYPTO_INITIALIZE = 4002;
	public static final int CRYPTO_GEN_KEK = 4003;
	public static final int CRYPTO_LOAD_CERT = 4004;
	public static final int CRYPTO_API_LOAD = 4005;
	public static final int CRYPTO_GEN_RANDOM = 4006;
	public static final int CRYPTO_DIGEST = 4007;
	public static final int CRYPTO_HMAC = 4008;
	public static final int CRYPTO_ENCRYPT_KEY = 4009;
	public static final int CRYPTO_DECRYPT_KEY = 4010;
	public static final int CRYPTO_ENCRYPT = 4011;
	public static final int CRYPTO_DECRYPT = 4012;
	public static final int CRYPTO_ENCRYPT_PRIVATEKEY = 4013;
	public static final int CRYPTO_DECRYPT_PRIVATEKEY = 4014;
	public static final int CRYPTO_ENCRYPT_PUBLICKEY = 4015;
	public static final int CRYPTO_DECRYPT_PUBLICKEY = 4016;
	public static final int CRYPTO_SIGNATURE = 4017;
	public static final int CRYPTO_VERIFY = 4018;
	public static final int CRYPTO_GEN_SECRETKEY = 4019;
	public static final int CRYPTO_ENCRYPT_SEK = 4020;
	public static final int CRYPTO_DECRYPT_SEK = 4021;
	public static final int CRYPTO_DECRYPT_DEK = 4022;
	public static final int CRYPTO_ENCRYPT_PARAM = 4023;
	public static final int CRYPTO_DECRYPT_PARAM = 4024;
	public static final int CRYPTO_PARAM_SIZE = 4025;
	public static final int CRYPTO_HASH_DATA = 4026;
	public static final int CRYPTO_GET_CERT = 4027;
	public static final int CRYPTO_GEN_ENVELOPED = 4028;
	public static final int CRYPTO_PROC_ENVELOPED = 4029;
	public static final int CRYPTO_GEN_SIGNED = 4030;
	public static final int CRYPTO_PROC_SIGNED = 4031;
	public static final int CRYPTO_VERIFY_CERT = 4032;
	public static final int CRYPTO_VERIFY_IVS = 4033;
	public static final int CRYPTO_VERIFY_CRL = 4034;
	public static final int CRYPTO_VERIFY_OCSP = 4035;

	public static final int CRYPTO_KEY_PAIR = 4037;
	public static final int CRYPTO_GEN_CERT = 4038;
	public static final int CRYPTO_GEN_PUBLIC = 4039;
	public static final int CRYPTO_GEN_PRIVATE = 4040;

	public static final int LICENSE_VERIFY = 5000;

	public static final int ERR_IDP_METADATA = 6000;
	public static final int ERR_GEN_METADATA = 6001;

	// 사용자인증서 로그인 관련 (MagicLine)
	public static final int E_ML_COM_ERR = 7000;

	public static final int API_EMPTY_DATA = 8000;
	public static final int API_EMPTY_COMMAND = 8001;
	public static final int API_EMPTY_COMMAND_DATA = 8002;
	public static final int API_INVALID_COMMAND = 8003;
	public static final int API_NON_EXISTENT_USERS = 8100;
	public static final int API_PASSWORD_MISMATCH = 8101;
	public static final int API_UPDATE_ZERO = 8102;
	public static final int API_EXCEPTION = 8999;

	// EAM Api 85xx
	public static final int API_ROLE_ERR_TIME_OUT = 8500;
	public static final int API_ROLE_ERR_ROLE_EMPTY = 8501;
	public static final int API_ROLE_ERR_INVALID_PARAMETER = 8502;
	public static final int API_ROLE_ERR_SESSION_INVALID = 8503;
	public static final int API_ROLE_ERR_EXCEPTION = 8504;

	// OIDC
	public static final int ERR_UNKNOWN_ENDPOINT = 9000;
	public static final int ERR_DUPLICATE_PARAMETER = 9001;
	public static final int ERR_SERVER_EXCEPTION = 9002;
	public static final int ERR_CLIENT_NOT_EXIST = 9003;
	public static final int ERR_CLIENT_DISABLED = 9004;
	public static final int ERR_MISMATCH_RESPONSE_TYPE = 9005;
	public static final int ERR_INVALID_SCOPE = 9006;
	public static final int ERR_INVALID_REDIRECT_URI = 9007;
	public static final int ERR_SUBAUTHSESSION_ID_NOT_EXIST = 9008;
	public static final int ERR_SUBAUTHSESSION_NOT_EXIST = 9009;
	
	public static final int ERR_ROOTAUTHSESSION_ID_NOT_EXIST = 9010;	
	public static final int ERR_ROOTAUTHSESSION_NOT_EXIST = 9011;
	public static final int ERR_USER_PW_NOT_EXIST = 9012;
	public static final int ERR_USER_ID_NOT_EXIST = 9013;
	public static final int ERR_AUTH_CODE_NOT_EXIST = 9014;
	public static final int ERR_AUTH_CODE_AUTH_CODE_EXPIRED = 9015;
	public static final int ERR_MISMATCH_GRANT_TYPE = 9016;
	public static final int ERR_MISMATCH_CLIENT_SECRET = 9017;
	public static final int ERR_PKCE_NOT_EXIST = 9018;
	public static final int ERR_PKCE_FAIL = 9019;
	
	public static final int ERR_MISMATCH_CLIENT_ID_CUR_SESSION = 9020;	
	public static final int ERR_MISMATCH_REDIRECT_URI_CUR_SESSION = 9021;
	public static final int ERR_LOGIN_TOKEN_NOT_EXIST = 9022;
	public static final int ERR_AUTH_SESSION_INVALID = 9023;
	public static final int ERR_LOGIN_TOKEN_ERROR_FORMAT = 9024;
	public static final int ERR_TOKEN_VERIFY_FAIL = 9025;
	public static final int ERR_AUTHORIZATION_HEADER_EMPTY = 9026;
	public static final int ERR_AUTHORIZATION_HEADER_PARSE_FAIL = 9027;
	public static final int ERR_MISMATCH_AUTHORIZATION_HEADER_TYPE = 9028;
	public static final int ERR_AUTHORIZATION_HEADER_CREDENTIALS_PARSE_FAIL = 9029;
	
	public static final int ERR_DECODE_AUTHORIZATION_HEADER = 9030;	
	public static final int ERR_REFRESH_TOKEN_DISABLED = 9031;
	public static final int ERR_REFRESH_TOKEN_ERROR_FORMAT = 9032;
	public static final int ERR_MISMATCH_TOKEN_TYPE = 9033;
	public static final int ERR_TOKEN_SID_PARSE_FAIL = 9034;
	public static final int ERR_MISMATCH_TOKEN_CUR_SESSION = 9035;
	public static final int ERR_MISMATCH_CLAIM_ISS = 9036;
	public static final int ERR_MISMATCH_CLAIM_AUD = 9037;
	public static final int ERR_TOKEN_EXPIRED = 9038;
	public static final int ERR_ACCESS_TOKEN_ERROR_FORMAT = 9039;	

	public static final int ERR_ID_TOKEN_ERROR_FORMAT = 9040;
	public static final int ERR_TOKEN_ERROR_FORMAT = 9041;
	public static final int ERR_REQ_PARAMETER_EMPTY = 9042;
	public static final int ERR_UNSUPPORTED_GRANT_TYPE = 9043;
	public static final int ERR_CLAIM_TYP_EMPTY = 9044;
	public static final int ERR_OIDC_LOGIN_FAIL = 9045;
	public static final int ERR_USER_ID_LOCK = 9046;
	public static final int ERR_USER_ID_RETIREMENT = 9047;
	public static final int ERR_USER_DUP_LOGIN = 9048;
	public static final int ERR_USER_PW_NOT_MATCH = 9049;
	public static final int ERR_UNKNOWN_TOKEN_TYPE = 9050;
	
	public static final int ERR_USER_NOT_EXIST = 9051;
	public static final int ERR_RELAY_STATE_NOT_EXIST = 9052;
	public static final int ERR_NONCE_NULL = 9053;

	public static final int ERR_CLIENT_OIDC_SETTING_ERROR = 9500;
	public static final int ERR_CLIENT_REPOSITORY_GET_FAIL = 9501;
	public static final int ERR_CLIENT_MISMATCH_STATE = 9502;
	public static final int ERR_CLIENT_OIDC_TOKEN_NULL = 9503;
	public static final int ERR_CLIENT_REFRESH_TOKEN_NULL = 9504;
	public static final int ERR_CLIENT_MISMATCH_CLAIM_NONCE = 9505;
	public static final int ERR_CLIENT_MISMATCH_CLAIM_ATHASH = 9506;
	public static final int ERR_CLIENT_MISMATCH_CLAIM_ISS = 9507;
	public static final int ERR_CLIENT_MISMATCH_CLAIM_AUD = 9508;
	public static final int ERR_CLIENT_ACCESS_TOKEN_FORMAT = 9509;

	public static final int ERR_CLIENT_ID_TOKEN_FORMAT = 9510;
	public static final int ERR_CLIENT_REFRESH_TOKEN_FORMAT = 9511;
	public static final int ERR_CLIENT_TOKEN_EXPIRED = 9512;
	public static final int ERR_CLIENT_INVALID_SCOPE = 9513;
	public static final int ERR_CLIENT_TOKEN_VERIFY_FAIL = 9514;
	public static final int ERR_CLIENT_REFRESH_TOKEN_DISABLED = 9515;
	public static final int ERR_CLIENT_EXCEPTION = 9516;
	public static final int ERR_CLIENT_RES_DATA = 9517;
	public static final int ERR_CLIENT_SESSION_INVALID = 9518;
	public static final int ERR_CLIENT_RES_PARAMETER_EMPTY = 9519;
	public static final int ERR_CLIENT_ID_TOKEN_NULL = 9520;
	public static final int ERR_CLIENT_ACCESS_TOKEN_NULL = 9521;
	public static final int ERR_CLIENT_NONCE_NULL = 9522;
	public static final int ERR_CLIENT_UNKNOWN_TOKEN_TYPE = 9523;

	public static final String SA_PROC_MSG = "ProcMsg";

	public static final String DEF_COM = "SSO";
	public static final String DEF_SEED = "_Dream_MagicSSO_";

	// OIDC
	public static final String ID_TOKEN_TYPE = "IDToken";
	public static final String ACCESS_TOKEN_TYPE = "AccessToken";
	public static final String REFRESH_TOKEN_TYPE = "RefreshToken";
	public static final String IDENTITY_TOKEN_TYPE = "IdentityToken";
	public static final String REFRESH_TOKEN = "refresh_token";
	public static final String AUTHORIZATION_CODE = "authorization_code";

	public static final int AUTHORIZATION_CODE_GRANT_TYPE = 1;
	public static final int REFRESH_TOKEN_GRANT_TYPE = 0;

	public static final String AUTHORIZATION_HEADER_TYPE_BASIC = "Basic";
	public static final String AUTHORIZATION_HEADER_TYPE_BEARER = "Bearer";
}