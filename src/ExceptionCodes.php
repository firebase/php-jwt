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
    public const SIGN_ALGORITHM_NOT_SUPPORTED = 9;
    public const KEY_IS_NOT_STRING = 10;
    public const OPENSSL_CAN_NOT_SIGN_DATA = 11;
    public const SODIUM_KEY_IS_NOT_STRING = 12;
    public const SODIUM_EXCEPTION = 13;
    public const SIGN_GENERAL_EXCEPTION = 14;
    public const VERIFY_ALGORITHM_NOT_SUPPORTED = 15;
    public const VERIFY_OPEN_SSL_ERROR = 16;
    public const VERIFY_SODIUM_NOT_AVAILABLE = 17;
    public const VERIFY_KEY_MATERIAL_IS_NOT_STRING = 18;
    public const VERIFY_SODIUM_EXCEPTION = 19;
    public const VERIFY_KEY_IS_NOT_STRING = 20;
    public const DECODED_JSON_IS_NULL = 21;
    public const ENCODED_JSON_IS_NULL = 22;
    public const INVALID_JSON = 23;
    public const KID_IS_EMPTY = 24;
    public const KID_IS_INVALID = 25;
    public const JSON_ERROR = 26;

    public const KEY_ID_NOT_FOUND = 27;
    public const OFFSET_SET_METHOD_NOT_IMPLEMENTED = 28;
    public const OFFSET_UNSET_METHOD_NOT_IMPLEMENTED = 29;

    public const JWKS_URI_IS_EMPTY = 30;

    public const JWK_MISSING_KEYS = 31;
    public const JWT_KEYS_IS_EMPTY = 32;
    public const JWT_ALGORITHM_NOT_SUPPORTED = 33;
    public const JWK_IS_EMPTY = 34;
    public const JWT_MISSING_KTY_PARAMETER = 35;
    public const JWT_MISSING_ALG_PARAMETER = 36;
    public const JWT_RSA_KEYS_NOT_SUPPORTED = 37;
    public const JWT_RSA_KEYS_MISSING_N_AND_E = 38;
    public const JWT_OPEN_SSL_ERROR = 39;
    public const JWK_EC_D_IS_NOT_SET = 40;
    public const JWT_EC_CRV_IS_EMPTY = 41;
    public const JWK_UNSUPPORTED_EC_CURVE = 42;
    public const JWT_X_AND_Y_ARE_EMPTY = 42;

    public const KEY_MATERIAL_IS_INVALID = 43;
    public const KEY_MATERIAL_IS_EMPTY = 44;
    public const KEY_ALGORITHM_IS_EMPTY = 45;
}
