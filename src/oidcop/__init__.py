import secrets

__version__ = "2.4.1"

DEF_SIGN_ALG = {
    "id_token": "RS256",
    "userinfo": "RS256",
    "request_object": "RS256",
    "client_secret_jwt": "HS256",
    "private_key_jwt": "RS256",
}

HTTP_ARGS = ["headers", "redirections", "connection_type"]

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

URL_ENCODED = "application/x-www-form-urlencoded"
JSON_ENCODED = "application/json"
JOSE_ENCODED = "application/jose"


def sanitize(txt):
    return txt


def rndstr(size=16):
    """
    Returns a string of random url safe characters

    :param size: The length of the string
    :return: string
    """
    return secrets.token_urlsafe(size)
    # chars = string.ascii_letters + string.digits
    # return "".join(choice(chars) for i in range(size))
