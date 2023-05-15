from abc import ABC, abstractmethod

class TPotProperty(ABC):
    def __init__(self, tag: str) -> None:
        self._tag = tag

    @property
    def tag(self):
        return self._tag
    
    @abstractmethod
    def extract(parser):
        pass

    @abstractmethod
    def get_data_from_source(source):
        pass


class HoneypotType(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['type']
    

class UserAgent(TPotProperty):
    def extract(self, parser):
        return parser.get_from_headers(self)
    
    def get_data_from_source(self, source):
        if source.get('user_agent') != None:
            return source['user_agent']
    

class SourceIP(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['src_ip']
    

class DestinationIP(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['dest_ip']
    

class SourcePort(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['src_port']
    

class DestPort(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['dest_port']
    

class Country(TPotProperty):
    def extract(self, parser):
        return parser.get_from_geoip(self)
    
    def get_data_from_source(self, source):
        if source.get('country_name') != None:
            return source['country_name']
    

class HTTPMethod(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['method']
    

class Timestamp(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['timestamp']
    

class Uri(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['path']
    

class IPReputation(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        if source.get('ip_rep') != None:
            return source['ip_rep']
    

class Credentials(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        if source.get('post_data') != None:
            return source['post_data']
        
class Protocol(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        return source['proto']
    

class SuricataSignature(TPotProperty):
    def extract(self, parser):
        return parser.get_from_suricata_alert(self)
    
    def get_data_from_source(self, source):
        return source['signature']
    

class Payload(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        if source.get('payload') != None and source.get('payload') != "":
            return source['payload']
        

class PayloadPrintable(TPotProperty):
    def extract(self, parser):
        return parser.get_from_source(self)
    
    def get_data_from_source(self, source):
        if source.get('payload_printable') != "":
            return source['payload_printable']
        

class Files(TPotProperty):
    def extract(self, parser):
        return parser.get_from_files(self)
    
    def get_data_from_source(self, source):
        return [file['md5'] for file in source if file.get('md5') != None and file.get('md5') != ""]
    

class FattHTTPMethod(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_http(self)
    
    def get_data_from_source(self, source):
        if source.get('requestMethod') != None:
            return source['requestMethod']
    

class FattFullUri(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_http(self)
    
    def get_data_from_source(self, source):
        if source.get('requestFullURI') != None:
            return source['requestFullURI']
    

class FattClientHeaderHash(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_http(self)
    
    def get_data_from_source(self, source):
        if source.get('clientHeaderHash') != None:
            return source['clientHeaderHash']
    

class FattUserAgent(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_http(self)
    
    def get_data_from_source(self, source):
        if source.get('userAgent') != None:
            return source['userAgent']
        

class FattServerName(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_tls(self)
    
    def get_data_from_source(self, source):
        if source.get('serverName') != None and source.get('serverName') != "":
            return source['serverName']
        

class FattJa3Algorithms(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_tls(self)
    
    def get_data_from_source(self, source):
        if source.get('ja3Algorithms') != None:
            return source['ja3Algorithms']
        

class FattJa3Ciphers(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_tls(self)
    
    def get_data_from_source(self, source):
        if source.get('ja3Ciphers') != None:
            return source['ja3Ciphers']
        

class FattJa3(TPotProperty):
    def extract(self, parser):
        return parser.get_from_fatt_tls(self)
    
    def get_data_from_source(self, source):
        if source.get('ja3') != None:
            return source['ja3']