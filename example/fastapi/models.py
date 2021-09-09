from typing import List
from typing import Optional

from pydantic import BaseModel


class WebFingerRequest(BaseModel):
    rel: Optional[str] = 'http://openid.net/specs/connect/1.0/issuer'
    resource: str


class AuthorizationRequest(BaseModel):
    acr_values: Optional[List[str]]
    claims: Optional[dict]
    claims_locales: Optional[List[str]]
    client_id: str
    display: Optional[str]
    id_token_hint: Optional[str]
    login_hint: Optional[str]
    max_age: Optional[int]
    nonce: Optional[str]
    prompt: Optional[List[str]]
    redirect_uri: str
    registration: Optional[dict]
    request: Optional[str]
    request_uri: Optional[str]
    response_mode: Optional[str]
    response_type: List[str]
    scope: List[str]
    state: Optional[str]
    ui_locales: Optional[List[str]]
