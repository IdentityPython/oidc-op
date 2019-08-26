# oidc-op
A couple of examples of a OIDC OPs.
One using CherryPy an the other Flask.

This is something you can play with.

This is **NOT** something you should even imaging running as a service.

## Flask setup

````
pip install flask pyyaml
cd oidc-op/flask_op
python -m flask_op.server flask_op/conf.yaml
````
