from abc import ABC, abstractmethod


class TPotPropertiesInterface(ABC):
    @abstractmethod
    def get_from_source(property):
        pass

    @abstractmethod
    def get_from_geoip(property):
        pass

    @abstractmethod
    def get_from_headers(property):
        pass

    @abstractmethod
    def get_from_suricata_alert(property):
        pass

    @abstractmethod
    def get_from_files(property):
        pass

    @abstractmethod
    def get_from_fatt_http(property):
        pass

    @abstractmethod
    def get_from_fatt_tls(property):
        pass


class JSONExportTPot(TPotPropertiesInterface):
    def __init__(self, source):
        self._source = source

    def get_from_source(self, property):
        return property.get_data_from_source(self._source)
    
    def get_from_geoip(self, property):
        return property.get_data_from_source(self._source['geoip'])

    def get_from_headers(self, property):
        return property.get_data_from_source(self._source['headers'])
    
    def get_from_suricata_alert(self, property):
        return property.get_data_from_source(self._source['alert'])
    
    def get_from_files(self, property):
        if self._source.get('files') != None:
            return property.get_data_from_source(self._source['files'])
        
    def get_from_fatt_http(self, property):
        if self._source.get('fatt_http') != None:
            return property.get_data_from_source(self._source['fatt_http'])
        
    def get_from_fatt_tls(self, property):
        if self._source.get('fatt_tls') != None:
            return property.get_data_from_source(self._source['fatt_tls'])
