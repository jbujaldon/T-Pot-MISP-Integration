from pymisp import PyMISP

class MISP:
    def __init__(self, misp_url, misp_api_key):
        self._misp = PyMISP(misp_url, misp_api_key, False)