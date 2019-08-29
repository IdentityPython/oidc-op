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
or the following that takes `conf.py`:
````
cd flask_rp/chrp
./rp.py -t -k conf
````

###### Install
````
# better use a virtualenv first...
pip install git+https://github.com/rohe/oidc-op.git
pip install flask

# get usage examples
git clone https://github.com/rohe/oidc-op.git
````

###### Configure

````
cd oidc-op/

# configuration: create a private folder
cp -R flask_op/private .
cp flask_op/passwd.json private/

# change passwd.json to private/passwd.json
cp flask_op/conf.yaml private/

# copy or link the static folder
# in it there's jwks.json
ln -s flask_op/static .
````

###### Jwks files

see: https://cryptojwt.readthedocs.io/en/latest/keyhandling.html

You definitely need to use `cryptojwt.key_jar.init_key_jar` to create a syntactically correct JWKS file.
An easy way can be to configure the auto creation of jwks files directly in your conf.yaml file:

````
# in conf.yaml
#
OIDC_KEYS:
    'private_path': './private/jwks.json'
    'key_defs': *keydef
    'public_path': './static/jwks.json'
    # this will create the jwks files if they absent
    'read_only': False
````

`read_only: False` create on each execution the path with the jwks files. Change it to `True` once you have produced ones.

###### Run the server
````
python -m flask_op.server private/conf.yaml
````

Then open your browser to `https://127.0.0.1:5000/.well-known/openid-configuration`, or other resources configured into `conf.yaml`, to get OP informations.
