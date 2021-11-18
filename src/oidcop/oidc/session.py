import json
import logging
from typing import Optional
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

from cryptojwt import as_unicode
from cryptojwt import b64d
from cryptojwt.jwe.aes import AES_GCMEncrypter
from cryptojwt.jwe.utils import split_ctx_and_tag
from cryptojwt.jws.exception import JWSException
from cryptojwt.jws.jws import factory
from cryptojwt.jws.utils import alg2keytype
from cryptojwt.jwt import JWT
from cryptojwt.utils import as_bytes
from cryptojwt.utils import b64e
from oidcmsg.exception import InvalidRequest
from oidcmsg.exception import VerificationError
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc.session import BACK_CHANNEL_LOGOUT_EVENT
from oidcmsg.oidc.session import EndSessionRequest

from oidcop import rndstr
from oidcop.client_authn import UnknownOrNoAuthnMethod
from oidcop.endpoint import Endpoint
from oidcop.endpoint_context import add_path
from oidcop.oauth2.authorization import verify_uri

logger = logging.getLogger(__name__)


def do_front_channel_logout_iframe(cinfo, iss, sid):
    """

    :param cinfo: Client info
    :param iss: Issuer ID
    :param sid: Session ID
    :return: IFrame
    """
    try:
        frontchannel_logout_uri = cinfo["frontchannel_logout_uri"]
    except KeyError:
        return None

    try:
        flsr = cinfo["frontchannel_logout_session_required"]
    except KeyError:
        flsr = False

    logger.debug(f"frontchannel_logout_uri: {frontchannel_logout_uri}")
    logger.debug(f"frontchannel_logout_session_required: {flsr}")
    if flsr:
        _query = {"iss": iss, "sid": sid}
        if "?" in frontchannel_logout_uri:
            p = urlparse(frontchannel_logout_uri)
            _args = parse_qs(p.query)
            _args.update(_query)
            _query = _args
            _np = p._replace(query="")
            frontchannel_logout_uri = _np.geturl()

        logger.debug(f"IFrame query: {_query}")
        _iframe = '<iframe src="{}?{}">'.format(
            frontchannel_logout_uri, urlencode(_query, doseq=True)
        )
    else:
        _iframe = '<iframe src="{}">'.format(frontchannel_logout_uri)

    return _iframe


class Session(Endpoint):
    request_cls = EndSessionRequest
    response_cls = Message
    request_format = "urlencoded"
    response_format = "urlencoded"
    response_placement = "url"
    endpoint_name = "end_session_endpoint"
    name = "session"
    default_capabilities = {
        "frontchannel_logout_supported": True,
        "frontchannel_logout_session_supported": True,
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "check_session_iframe": None,
    }

    def __init__(self, server_get, **kwargs):
        _csi = kwargs.get("check_session_iframe")
        if _csi and not _csi.startswith("http"):
            kwargs["check_session_iframe"] = add_path(server_get("endpoint_context").issuer, _csi)
        Endpoint.__init__(self, server_get, **kwargs)
        self.iv = as_bytes(rndstr(24))

    def _encrypt_sid(self, sid):
        encrypter = AES_GCMEncrypter(key=as_bytes(self.server_get("endpoint_context").symkey))
        enc_msg = encrypter.encrypt(as_bytes(sid), iv=self.iv)
        return as_unicode(b64e(enc_msg))

    def _decrypt_sid(self, enc_msg):
        _msg = b64d(as_bytes(enc_msg))
        encrypter = AES_GCMEncrypter(key=as_bytes(self.server_get("endpoint_context").symkey))
        ctx, tag = split_ctx_and_tag(_msg)
        return as_unicode(encrypter.decrypt(as_bytes(ctx), iv=self.iv, tag=as_bytes(tag)))

    def do_back_channel_logout(self, cinfo, sid):
        """

        :param cinfo: Client information
        :param sid: The session ID
        :return: Tuple with logout URI and signed logout token
        """

        _context = self.server_get("endpoint_context")

        try:
            back_channel_logout_uri = cinfo["backchannel_logout_uri"]
        except KeyError:
            return None

        # Create the logout token
        # always include sub and sid so I don't check for
        # backchannel_logout_session_required

        # enc_msg = self._encrypt_sid(sid)

        payload = {"sid": sid, "events": {BACK_CHANNEL_LOGOUT_EVENT: {}}}

        try:
            alg = cinfo["id_token_signed_response_alg"]
        except KeyError:
            alg = _context.provider_info["id_token_signing_alg_values_supported"][0]

        _jws = JWT(_context.keyjar, iss=_context.issuer, lifetime=86400, sign_alg=alg)
        _jws.with_jti = True
        _logout_token = _jws.pack(payload=payload, recv=cinfo["client_id"])

        return back_channel_logout_uri, _logout_token

    def clean_sessions(self, usids):
        # Revoke all sessions
        _context = self.server_get("endpoint_context")
        for sid in usids:
            _context.session_manager.revoke_client_session(sid)

    def logout_all_clients(self, sid):
        _context = self.server_get("endpoint_context")
        _mngr = _context.session_manager
        _session_info = _mngr.get_session_info(
            sid, user_session_info=True, client_session_info=True, grant=True
        )

        # Front-/Backchannel logout ?
        _cdb = _context.cdb
        _iss = _context.issuer
        _user_id = _session_info["user_id"]
        logger.debug(
            f"(logout_all_clients) user_id={_user_id},  client_id={_session_info['client_id']}, "
            f"grant_id={_session_info['grant_id']}"
        )

        bc_logouts = {}
        fc_iframes = {}
        _rel_sid = []
        for _client_id in _session_info["user_session_info"].subordinate:
            # I prefer back-channel. Should it be configurable ?
            if "backchannel_logout_uri" in _cdb[_client_id]:
                _cli = _mngr.get([_user_id, _client_id])
                for gid in _cli.subordinate:
                    grant = _mngr.get([_user_id, _client_id, gid])
                    # Has to be connected to an authentication event
                    if not grant.authentication_event:
                        continue
                    idt = grant.last_issued_token_of_type("id_token")
                    if idt:
                        _rel_sid.append(idt.session_id)
                        _spec = self.do_back_channel_logout(_cdb[_client_id], idt.session_id)
                        if _spec:
                            bc_logouts[_client_id] = _spec
                        break
            elif "frontchannel_logout_uri" in _cdb[_client_id]:
                _cli = _mngr.get([_user_id, _client_id])
                for gid in _cli.subordinate:
                    grant = _mngr.get([_user_id, _client_id, gid])
                    # Has to be connected to an authentication event
                    if not grant.authentication_event:
                        continue
                    idt = grant.last_issued_token_of_type("id_token")
                    if idt:
                        _rel_sid.append(idt.session_id)
                        # Construct an IFrame
                        _spec = do_front_channel_logout_iframe(
                            _cdb[_client_id], _iss, idt.session_id
                        )
                        if _spec:
                            fc_iframes[_client_id] = _spec
                        break

        self.clean_sessions(_rel_sid)

        res = {}
        if bc_logouts:
            res["blu"] = bc_logouts
        if fc_iframes:
            res["flu"] = fc_iframes
        return res

    def unpack_signed_jwt(self, sjwt, sig_alg=""):
        _jwt = factory(sjwt)
        if _jwt:
            if sig_alg:
                alg = sig_alg
            else:
                alg = self.kwargs["signing_alg"]

            sign_keys = self.server_get("endpoint_context").keyjar.get_signing_key(alg2keytype(alg))
            _info = _jwt.verify_compact(keys=sign_keys, sigalg=alg)
            return _info
        else:
            raise ValueError("Not a signed JWT")

    def logout_from_client(self, sid):
        _context = self.server_get("endpoint_context")
        _cdb = _context.cdb
        _session_information = _context.session_manager.get_session_info(sid, grant=True)
        _client_id = _session_information["client_id"]

        res = {}
        if "backchannel_logout_uri" in _cdb[_client_id]:
            _spec = self.do_back_channel_logout(_cdb[_client_id], sid)
            if _spec:
                res["blu"] = {_client_id: _spec}
        elif "frontchannel_logout_uri" in _cdb[_client_id]:
            # Construct an IFrame
            _spec = do_front_channel_logout_iframe(_cdb[_client_id], _context.issuer, sid)
            if _spec:
                res["flu"] = {_client_id: _spec}

        self.clean_sessions([sid])
        return res

    def process_request(
        self,
        request: Optional[Union[Message, dict]] = None,
        http_info: Optional[dict] = None,
        **kwargs,
    ):
        """
        Perform user logout

        :param request:
        :param http_info:
        :param kwargs:
        :return:
        """
        _context = self.server_get("endpoint_context")
        _mngr = _context.session_manager

        if "post_logout_redirect_uri" in request:
            if "id_token_hint" not in request:
                raise InvalidRequest("If post_logout_redirect_uri then id_token_hint is a MUST")
        _cookies = http_info.get("cookie")
        _session_info = None

        if _cookies:
            logger.debug("parse_cookie@session")
            _cookie_name = _context.cookie_handler.name["session"]
            try:
                _cookie_infos = _context.cookie_handler.parse_cookie(
                    cookies=_cookies, name=_cookie_name
                )
            except VerificationError:
                raise InvalidRequest("Cookie error")

            if _cookie_infos:
                # value is a JSON document
                _cookie_info = json.loads(_cookie_infos[0]["value"])
                logger.debug("process_request: cookie_info={}".format(_cookie_info))
                try:
                    _session_info = _mngr.get_session_info(_cookie_info["sid"], grant=True)
                except KeyError:
                    raise ValueError("Can't find any corresponding session")

        if _session_info is None:
            logger.debug("No relevant cookie")
            raise ValueError("Missing cookie")

        if "id_token_hint" in request and _session_info:
            _id_token = request[verified_claim_name("id_token_hint")]
            logger.debug("ID token hint: {}".format(_id_token))

            _aud = _id_token["aud"]
            if _session_info["client_id"] not in _aud:
                raise ValueError("Client ID doesn't match")

            if _id_token["sub"] != _session_info["grant"].sub:
                raise ValueError("Sub doesn't match")
        else:
            _aud = []

        # _context.cdb[_session_info["client_id"]]

        # verify that the post_logout_redirect_uri if present are among the ones
        # registered

        try:
            _uri = request["post_logout_redirect_uri"]
        except KeyError:
            if _context.issuer.endswith("/"):
                _uri = "{}{}".format(_context.issuer, self.kwargs["post_logout_uri_path"])
            else:
                _uri = "{}/{}".format(_context.issuer, self.kwargs["post_logout_uri_path"])
            plur = False
        else:
            plur = True
            verify_uri(
                _context,
                request,
                "post_logout_redirect_uri",
                client_id=_session_info["client_id"],
            )

        payload = {
            "sid": _session_info["session_id"],
        }

        # redirect user to OP logout verification page
        if plur and "state" in request:
            _uri = "{}?{}".format(_uri, urlencode({"state": request["state"]}))
            payload["state"] = request["state"]

        payload["redirect_uri"] = _uri

        logger.debug("JWS payload: {}".format(payload))
        # From me to me
        _jws = JWT(
            _context.keyjar,
            iss=_context.issuer,
            lifetime=86400,
            sign_alg=self.kwargs["signing_alg"],
        )
        sjwt = _jws.pack(payload=payload, recv=_context.issuer)

        location = "{}?{}".format(self.kwargs["logout_verify_url"], urlencode({"sjwt": sjwt}))
        return {"redirect_location": location}

    def parse_request(self, request, http_info=None, **kwargs):
        """

        :param request:
        :param auth:
        :param kwargs:
        :return:
        """

        if not request:
            request = {}

        # Verify that the client is allowed to do this
        try:
            auth_info = self.client_authentication(request, http_info, **kwargs)
        except UnknownOrNoAuthnMethod:
            pass
        else:
            if not auth_info:
                pass
            elif isinstance(auth_info, ResponseMessage):
                return auth_info
            else:
                request["client_id"] = auth_info["client_id"]
                request["access_token"] = auth_info["token"]

        if isinstance(request, dict):
            _context = self.server_get("endpoint_context")
            request = self.request_cls(**request)
            if not request.verify(keyjar=_context.keyjar, sigalg=""):
                raise InvalidRequest("Request didn't verify")
            # id_token_signing_alg_values_supported
            try:
                _ith = request[verified_claim_name("id_token_hint")]
            except KeyError:
                pass
            else:
                if (
                    _ith.jws_header["alg"]
                    not in _context.provider_info["id_token_signing_alg_values_supported"]
                ):
                    raise JWSException("Unsupported signing algorithm")

        return request

    def do_verified_logout(self, sid, alla=False, **kwargs):
        logger.debug(f"(do_verified_logout): sid={sid}")
        if alla:
            _res = self.logout_all_clients(sid=sid)
        else:
            _res = self.logout_from_client(sid=sid)

        bcl = _res.get("blu")
        if bcl:
            _context = self.server_get("endpoint_context")
            # take care of Back channel logout first
            for _cid, spec in bcl.items():
                _url, sjwt = spec
                logger.info("logging out from {} at {}".format(_cid, _url))

                res = _context.httpc.post(
                    _url,
                    data="logout_token={}".format(sjwt),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    **_context.httpc_params,
                )

                if res.status_code < 300:
                    logger.info("Logged out from {}".format(_cid))
                elif res.status_code in [501, 504]:
                    logger.info("Got a %s which is acceptable", res.status_code)
                elif res.status_code >= 400:
                    logger.info("failed to logout from {}".format(_cid))

        return _res["flu"].values() if _res.get("flu") else []

    def kill_cookies(self):
        _context = self.server_get("endpoint_context")
        _handler = _context.cookie_handler
        session_mngmnt = _handler.make_cookie_content(
            value="", name=_handler.name["session_management"], max_age=-1
        )
        session = _handler.make_cookie_content(value="", name=_handler.name["session"], max_age=-1)
        return [session_mngmnt, session]
