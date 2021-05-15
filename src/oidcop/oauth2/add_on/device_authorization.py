def add_support(endpoint, **kwargs):
    _context = endpoint["token"].endpoint_context

    _db = kwargs.get("db")
    if not _db:
        _context.dev_auth_db = {}
