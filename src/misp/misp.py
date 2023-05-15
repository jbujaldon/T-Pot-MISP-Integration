from abc import ABC, abstractmethod
from pymisp import PyMISP
from pymisp.mispevent import MISPEvent, MISPAttribute

class MISP:
    def __init__(self, misp_url, misp_api_key):
        self._misp = PyMISP(misp_url, misp_api_key, False)

    @abstractmethod
    def parse(self, data: list):
        pass

    def create_event(self, type: str):
        event = MISPEvent()
        event.info = "TPot attack in {}".format(type)
        event.distribution = 0
        event.threat_level_id = 4
        event.analysis = 1
        return event
    
    def create_attribute(self, tag, value):
        type = self.get_attribute_type(tag)
        attribute = MISPAttribute()
        attribute.type = type
        attribute.category = self.get_attribute_category(type)
        return attribute
    
    def get_attribute_category(self, type: str):
        pass

    def get_attribute_type(self, tag: str):
        pass
    
    def save_event(self, event: MISPEvent):
        self._misp.add_event(event)
