import logging
import re

from functools import cmp_to_key

from cryptojwt import jwe
from cryptojwt.jws.jws import SIGNER_ALGS

ALG_SORT_ORDER = {"RS": 0, "ES": 1, "HS": 2, "PS": 3, "no": 4}
WEAK_ALGS = ["RSA1_5", "none"]

logger = logging.getLogger(__name__)


def sort_sign_alg(alg1, alg2):
    if ALG_SORT_ORDER[alg1[0:2]] < ALG_SORT_ORDER[alg2[0:2]]:
        return -1

    if ALG_SORT_ORDER[alg1[0:2]] > ALG_SORT_ORDER[alg2[0:2]]:
        return 1

    if alg1 < alg2:
        return -1

    if alg1 > alg2:
        return 1

    return 0


def assign_algorithms(typ):
    if typ == "signing_alg":
        # Pick supported signing algorithms from crypto library
        # Sort order RS, ES, HS, PS
        sign_algs = list(SIGNER_ALGS.keys())
        return sorted(sign_algs, key=cmp_to_key(sort_sign_alg))
    elif typ == "encryption_alg":
        return jwe.SUPPORTED["alg"]
    elif typ == "encryption_enc":
        return jwe.SUPPORTED["enc"]


def construct_endpoint_info(default_capabilities, **kwargs):
    if default_capabilities is None:
        return default_capabilities

    _info = {}
    for attr, default_val in default_capabilities.items():
        if attr in kwargs:
            _proposal = kwargs[attr]
            _permitted = None

            if "signing_alg_values_supported" in attr:
                _permitted = set(assign_algorithms("signing_alg"))
            elif "encryption_alg_values_supported" in attr:
                _permitted = set(assign_algorithms("encryption_alg"))
            elif "encryption_enc_values_supported" in attr:
                _permitted = set(assign_algorithms("encryption_enc"))

            if _permitted and not _permitted.issuperset(set(_proposal)):
                raise ValueError(
                    "Proposed set of values outside set of permitted, "
                    f"'{attr}' sould be {_permitted} it's instead {_proposal}"
                )
            _info[attr] = _proposal
        else:
            if default_val is not None:
                _info[attr] = default_val
            elif "signing_alg_values_supported" in attr:
                _info[attr] = assign_algorithms("signing_alg")
                if "none" in _info[attr]:
                    _info[attr].remove("none")
            elif "encryption_alg_values_supported" in attr:
                # RSA1_5 not among defaults
                _info[attr] = [s for s in assign_algorithms("encryption_alg") if s not in WEAK_ALGS]
            elif "encryption_enc_values_supported" in attr:
                _info[attr] = assign_algorithms("encryption_enc")

        if re.match(r".*(alg|enc).*_values_supported", attr):
            for i in _info[attr]:
                if i in WEAK_ALGS:
                    logger.warning(
                        f"Found {i} in {attr}. This is a weak algorithm "
                        "that MUST not be used in production!"
                    )
    return _info
