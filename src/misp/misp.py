from abc import ABC, abstractmethod
from pymisp import PyMISP
from pymisp.mispevent import MISPEvent, MISPAttribute


class MISP:
    def __init__(self, misp_url, misp_api_key):
        self._misp = PyMISP(misp_url, misp_api_key, False)

    @abstractmethod
    def parse(self, data: list):
        pass

    def add_new_event(self, type: str):
        event = MISPEvent()
        event.info = "TPot attack in {}".format(type)
        event.distribution = 0
        event.threat_level_id = 4
        event.analysis = 1
        return self._misp.add_event(event, pythonify=True).id
    
    def add_new_attribute_to_event(self, event_id, tag, value):
        if tag != 'type':
            type = self.get_attribute_type(tag)
            attribute = MISPAttribute()
            attribute.type = type
            attribute.category = self.get_attribute_category(type)
            if value != '' and value != None:
                attribute.value = value
                return self._misp.add_attribute(event_id, attribute, pythonify=True)
    
    def get_attribute_type(self, tag: str):
        if tag == 'country':
            return 'country-of-residence'
        elif tag == 'dest-port' or tag == 'src-port':
            return 'port'
        elif tag == 'user-agent':
            return 'user-agent'
        elif tag == 'http-method':
            return 'http-method'
        elif tag == 'ip-reputation':
            return 'comment'
        elif tag == 'src-ip' or tag == 'dest-ip':
            return 'ip-src'
        elif tag == 'timestamp':
            return 'datetime'
        elif tag == 'uri' or tag == 'full-uri':
            return 'uri'
        elif tag == 'protocol' or tag == 'suricata-signature' or tag == 'client-header-hash':
            return 'other'
        elif tag == 'payload' or tag == 'payload-printable':
            return 'anonymised'
        elif tag == 'ja3' or tag == 'ja3-algorithms' or tag == 'ja3-ciphers':
            return 'ja3-fingerprints-md5'
        elif tag == 'server-name':
            return 'text'
    
    def get_attribute_category(self, type: str):
        if type == 'country-of-residence':
            return 'Person'
        elif type == 'port' or type == 'http-method' or type == 'comment' or type == 'ip-src' or type == 'uri' or type == 'text' or type == 'user-agent':
            return 'Network activity'
        elif type == 'datetime' or type == 'other':
            return 'Other'
        elif type == 'anonymised' or type == 'ja3-fingerprints-md5':
            return 'Payload delivery'
