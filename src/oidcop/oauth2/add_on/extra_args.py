def pre_construct(response_args, request, endpoint_context, **kwargs):
    """
    Add extra arguments to the request.

    :param response_args:
    :param request:
    :param endpoint_context:
    :param kwargs:
    :return:
    """

    _extra = endpoint_context.add_on.get("extra_args")
    if _extra:
        for arg, _param in _extra.items():
            _val = endpoint_context.get(_param)
            if _val:
                request[arg] = _val

    return request


def add_support(endpoint, **kwargs):
    #
    _added = False
    for endpoint_name in list(kwargs.keys()):
        _endp = endpoint[endpoint_name]
        _endp.pre_construct.append(pre_construct)

        if _added is False:
            _endp.server_get("endpoint_context").add_on["extra_args"] = kwargs
            _added = True
