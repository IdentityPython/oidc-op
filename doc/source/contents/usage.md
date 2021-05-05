Usage
-----

Some examples, how to run flask_op and django_op, but also some typical configuration in relation to common use cases.



Configure flask-rp
------------------

_JWTConnect-Python-OidcRP_ is Relaing Party for tests, see [related page](https://github.com/openid/JWTConnect-Python-OidcRP).
You can run a working instance of `JWTConnect-Python-OidcRP.flask_rp` with:

````
pip install git+https://github.com/openid/JWTConnect-Python-OidcRP.git

# get entire project to have examples files
git clone https://github.com/openid/JWTConnect-Python-OidcRP.git
cd JWTConnect-Python-OidcRP

# run it as it come
python3 -m flask_rp.wsgi flask_rp/conf.yaml
````

Now you can connect to `https://127.0.0.1:8090/` to see the RP landing page and select your authentication endpoint.

### Authentication examples

![RP](doc/source/_images/1.png)

Get to the RP landing page to choose your authentication endpoint. The first option aims to use _Provider Discovery_.

----------------------------------

![OP Auth](doc/source/_images/2.png)

AS/OP accepted our authentication request and prompt to us the login form. Read passwd.json file to get credentials.

----------------------------------

![Access](doc/source/_images/3.png)

The identity representation with the information fetched from the user info endpoint.

----------------------------------

![Logout](doc/source/_images/4.png)

We can even test the single logout
