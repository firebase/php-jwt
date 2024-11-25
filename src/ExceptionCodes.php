<?php

namespace Firebase\JWT;

class ExceptionCodes
{
    public const KEY_NOT_EMPTY = 1;
    public const WRONG_NUMBER_OF_SEGMENTS = 2;
    public const INVALID_HEADER_ENCODING = 3;
    public const INVALID_CLAIMS_ENCODING = 4;
    public const PAYLOAD_NOT_JSON = 5;
    public const EMPTY_ALGORITHM = 6;
    public const DECODE_ALGORITHM_NOT_SUPPORTED = 7;
    public const INCORRECT_KEY_FOR_ALGORITHM = 8;
    public const SIGNATURE_VERIFICATION_FAILED = 9;
    public const NBF_PRIOR_TO_DATE = 10;
    public const IAT_PRIOR_TO_DATE = 11;
    public const TOKEN_EXPIRED = 12;
    public const SIGN_ALGORITHM_NOT_SUPPORTED = 13;
    public const KEY_IS_NOT_STRING = 14;
    public const OPENSSL_SIGNATURE = 15;
    public const OPENSSL_CAN_NOT_SIGN_DATA = 16;
    public const SODIUM_KEY_IS_NOT_STRING = 17;
    public const SODIUM_FUNC_DOES_NOT_EXIST = 18;
    public const SODIUM_KEY_LENGTH_ZERO = 19;
    public const SODIUM_VERIFY_KEY_LENGTH_ZERO = 20;
    public const SODIUM_VERIFY_SIGNATURE_EMPTY = 21;
    public const SODIUM_EXCEPTION = 22;
    public const SIGN_GENERAL_EXCEPTION = 23;
    public const VERIFY_ALGORITHM_NOT_SUPPORTED = 24;
    public const VERIFY_OPEN_SSL_ERROR = 25;
    public const VERIFY_SODIUM_NOT_AVAILABLE = 26;
    public const VERIFY_KEY_MATERIAL_IS_NOT_STRING = 27;
    public const VERIFY_SODIUM_EXCEPTION = 28;
    public const VERIFY_KEY_IS_NOT_STRING = 29;
    public const DECODED_JSON_IS_NULL = 30;
    public const ENCODED_JSON_IS_NULL = 31;
    public const INVALID_JSON = 32;
    public const KID_IS_EMPTY = 33;
    public const KID_IS_INVALID = 34;
    public const JSON_ERROR = 35;
    public const KEY_ID_NOT_FOUND = 36;
    public const OFFSET_SET_METHOD_NOT_IMPLEMENTED = 37;
    public const OFFSET_UNSET_METHOD_NOT_IMPLEMENTED = 38;
    public const JWKS_URI_IS_EMPTY = 39;
    public const JWK_MISSING_KEYS = 40;
    public const JWT_KEYS_IS_EMPTY = 41;
    public const JWT_ALGORITHM_NOT_SUPPORTED = 42;
    public const JWK_IS_EMPTY = 43;
    public const JWT_MISSING_KTY_PARAMETER = 44;
    public const JWT_MISSING_ALG_PARAMETER = 45;
    public const JWT_RSA_KEYS_NOT_SUPPORTED = 46;
    public const JWT_RSA_KEYS_MISSING_N_AND_E = 47;
    public const JWT_OPEN_SSL_ERROR = 48;
    public const JWK_EC_D_IS_NOT_SET = 49;
    public const JWT_EC_CRV_IS_EMPTY = 50;
    public const JWK_UNSUPPORTED_EC_CURVE = 51;
    public const JWT_X_AND_Y_ARE_EMPTY = 52;
    public const KEY_MATERIAL_IS_INVALID = 53;
    public const KEY_MATERIAL_IS_EMPTY = 54;
    public const KEY_ALGORITHM_IS_EMPTY = 55;
    public const CACHED_KEY_MISSING = 56;
    public const CACHED_KEY_EMPTY = 57;
    public const CACHED_KEY_GET_JWK = 58;
    public const JWK_OKP_MISSING = 59;
    public const JWT_CRV_MISSING = 60;
    public const JWT_CRV_UNSUPPORTED = 61;
    public const JWT_X_MISSING = 62;
}
