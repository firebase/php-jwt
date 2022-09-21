<?php

declare(strict_types=1);


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
    const OPENSSL_CAN_NOT_SIGN_DATA = 11;
    const SODIUM_KEY_IS_NOT_STRING = 12;
    const SODIUM_EXCEPTION = 13;
    const SIGN_GENERAL_EXCEPTION = 14;
    const VERIFY_ALGORITHM_NOT_SUPPORTED = 15;
    const VERIFY_OPEN_SSL_ERROR = 16;
    const VERIFY_SODIUM_NOT_AVAILABLE = 17;
    const VERIFY_KEY_MATERIAL_IS_NOT_STRING = 18;
    const VERIFY_SODIUM_EXCEPTION = 19;
    const VERIFY_KEY_IS_NOT_STRING = 20;
    const DECODED_JSON_IS_NULL = 21;
    const ENCODED_JSON_IS_NULL = 22;
    const INVALID_JSON = 23;
    const KID_IS_EMPTY = 24;
    const KID_IS_INVALID = 25;
    const JSON_ERROR = 26;

    const KEY_ID_NOT_FOUND = 27;
    const OFFSET_SET_METHOD_NOT_IMPLEMENTED = 28;
    const OFFSET_UNSET_METHOD_NOT_IMPLEMENTED = 29;

    const JWKS_URI_IS_EMPTY = 30;

    const JWK_MISSING_KEYS = 31;
    const JWT_KEYS_IS_EMPTY = 32;
    const JWT_ALGORITHM_NOT_SUPPORTED = 33;
    const JWK_IS_EMPTY = 34;
    const JWT_MISSING_KTY_PARAMETER = 35;
    const JWT_MISSING_ALG_PARAMETER = 36;
    const JWT_RSA_KEYS_NOT_SUPPORTED = 37;
    const JWT_RSA_KEYS_MISSING_N_AND_E = 38;
    const JWT_OPEN_SSL_ERROR = 39;
    const JWK_EC_D_IS_NOT_SET = 40;
    const JWT_EC_CRV_IS_EMPTY = 41;
    const JWK_UNSUPPORTED_EC_CURVE = 42;
    const JWT_X_AND_Y_ARE_EMPTY = 42;

    const KEY_MATERIAL_IS_INVALID = 43;
    const KEY_MATERIAL_IS_EMPTY = 44;
    const KEY_ALGORITHM_IS_EMPTY = 45;
}