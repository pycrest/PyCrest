class APIException(Exception):

    def __init__(self, *args, **kwargs):
        self.status_code = kwargs.pop("status_code", None)
        Exception.__init__(self, *args, **kwargs)
