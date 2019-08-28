# oidc-op
A couple of examples of a OIDC OPs.
One using CherryPy an the other Flask.

This is something you can play with.

This is **NOT** something you should even imaging running as a service.

#### Flask setup

It uses `JWTConnect-Python-OidcRP` for tests, see [related page](https://github.com/openid/JWTConnect-Python-OidcRP).
You can run `JWTConnect-Python-OidcRP.flask_rp` with:

````
python3 -m flask_rp.wsgi flask_rp/conf.yaml
````

Install, configure and run the OP:
````
# better use a virtualenv first...
pip install git+https://github.com/rohe/oidc-op.git
pip install flask

# get usage examples
git clone https://github.com/rohe/oidc-op.git
cd oidc-op/

# configuration: create a private folder
cp -R flask_op/private .
cp flask_op/passwd.json private/

# change passwd.json to private/passwd.json
cp flask_op/conf.yaml private/

# copy or link the static folder
# in it there's jwks.json
ln -s flask_op/static .

# put jwt and encryption keys here
# see: https://cryptojwt.readthedocs.io/en/latest/keyhandling.html
python -c 'import json; from cryptojwt.jwk.rsa import new_rsa_key; print(json.dumps(new_rsa_key().to_dict(), indent=2))' > private/cookie_sign_jwk.json

python -m flask_op.server private/conf.yaml
````

Then open your browser to `https://127.0.0.1:5000/.well-known/openid-configuration`, or other resources configured into `conf.yaml`, to get OP informations.
