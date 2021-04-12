from functools import cmp_to_key

from cryptojwt import jwe
from cryptojwt.jws.jws import SIGNER_ALGS

ALG_SORT_ORDER = {"RS": 0, "ES": 1, "HS": 2, "PS": 3, "no": 4}


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
    if default_capabilities is not None:
        _info = {}
        for attr, default_val in default_capabilities.items():
            try:
                _proposal = kwargs[attr]
            except KeyError:
                if default_val is not None:
                    _info[attr] = default_val
                elif "signing_alg_values_supported" in attr:
                    _info[attr] = assign_algorithms("signing_alg")
                    if attr == "token_endpoint_auth_signing_alg_values_supported":
                        # none must not be in
                        # token_endpoint_auth_signing_alg_values_supported
                        if "none" in _info[attr]:
                            _info[attr].remove("none")
                elif "encryption_alg_values_supported" in attr:
                    _info[attr] = assign_algorithms("encryption_alg")
                elif "encryption_enc_values_supported" in attr:
                    _info[attr] = assign_algorithms("encryption_enc")
            else:
                _permitted = None

                if "signing_alg_values_supported" in attr:
                    _permitted = set(assign_algorithms("signing_alg"))
                elif "encryption_alg_values_supported" in attr:
                    _permitted = set(assign_algorithms("encryption_alg"))
                elif "encryption_enc_values_supported" in attr:
                    _permitted = set(assign_algorithms("encryption_enc"))

                if _permitted and not _permitted.issuperset(set(_proposal)):
                    raise ValueError(
                        "Proposed set of values outside set of permitted ({})".__format__(
                            attr
                        )
                    )

                _info[attr] = _proposal
        return _info
    else:
        return None
