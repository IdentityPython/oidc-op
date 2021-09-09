#!/usr/bin/env python3
from oidcmsg.oidc import AuthorizationRequest

q = "state=https%3A%2F%2Fsbs.scz-vm.net%2Flanding%3Flogout%3Dtrue&client_id=sbs-server&nonce=4b8739fb-7bc9-48bb-bb1e-46f164b82864&response_mode=query&response_type=code&scope=profile+eduperson_scoped_affiliation+voperson_external_affiliation+email+ssh_public_key+eduperson_orcid+uid+voperson_external_id+eduperson_entitlement+eduperon_assurance+openid+eduperson_principal_name+voperson_id&acr_values=https%3A%2F%2Frefeds.org%2Fprofile%2Fmfa&claims=%7B%22userinfo%22%3A%7B%22acr%22%3A%7B%22value%22%3Anull%7D%7D%7D&redirect_uri=https%3A%2F%2Fsbs.scz-vm.net%2Fapi%2Fusers%2Fresume-session"

ar = AuthorizationRequest().from_urlencoded(q)
print(ar.to_dict())