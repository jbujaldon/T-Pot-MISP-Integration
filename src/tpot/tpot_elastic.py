from abc import ABC, abstractmethod
from elasticsearch import Elasticsearch
from tpot.tpot_parser import JSONExportTPot
from tpot import models

import itertools


class HoneypotStrategy(ABC):
    def __init__(self, es: Elasticsearch):
        self._es = es

    @property
    @abstractmethod
    def properties(self):
        pass

    @abstractmethod
    def request(self):
        pass

    def perform_request(self, query: str):
        response = self._es.search(query={"query_string": {"query": query}}, size=100)
        hits = response['hits']['hits']
        result_data = list()

        for hit in hits:
            parser = JSONExportTPot(hit['_source'])
            data = dict()
            for prop in self.properties():
                data[prop.tag] = prop.extract(parser)
            result_data.append(data)
        
        return result_data


class Tanner(HoneypotStrategy):
    def properties(self):
        return [
            models.HoneypotType("type"), 
            models.Country("country"),
            models.DestPort("dest-port"),
            models.HTTPMethod("http-method"),
            models.IPReputation("ip-reputation"),
            models.SourceIP("src-ip"),
            models.SourcePort("src-port"),
            models.Timestamp("timestamp"),
            models.Uri("uri"),
            models.UserAgent("user-agent")
        ]
    
    def request(self):
        return self.perform_request("Tanner")
    

class Suricata(HoneypotStrategy):
    def properties(self):
        return [
            models.HoneypotType("type"), 
            models.Country("country"),
            models.DestPort("dest-port"),
            models.IPReputation("ip-reputation"),
            models.SourceIP("src-ip"),
            models.SourcePort("src-port"),
            models.Timestamp("timestamp"),
            models.Uri("uri"),
            models.Protocol("protocol"),
            models.SuricataSignature("suricata-signature"),
            models.Payload("payload"),
            models.PayloadPrintable("payload-printable")
            # models.Files("files")
        ]
    
    def request(self):
        return self.perform_request("Suricata")
    

class Fatt(HoneypotStrategy):
    def properties(self):
        return [
            models.HoneypotType("type"),
            models.DestinationIP("dest-ip"),
            models.DestPort("dest-port"),
            models.SourceIP("src-ip"),
            models.SourcePort("src-port"),
            models.Timestamp("timestamp"),
            models.IPReputation("ip-reputation"),
            models.Uri("uri"),
            models.FattClientHeaderHash("client-header-hash"),
            models.FattFullUri("full-uri"),
            models.FattHTTPMethod("http-method"),
            models.FattUserAgent("user-agent"),
            models.FattJa3("ja3"),
            models.FattJa3Algorithms("ja3-algorithms"),
            models.FattJa3Ciphers("ja3-ciphers"),
            models.FattServerName("server-name"),
        ]
    
    def request(self):
        return self.perform_request("Fatt")


class TPotElasticParser:
    def __init__(self, elastic_url: str, elastic_user: str, elastic_pwd: str):
        self._es = Elasticsearch(elastic_url, basic_auth=(elastic_user, elastic_pwd), verify_certs=False)
        self._strategies = [
            Tanner(self._es),
            Suricata(self._es),
            Fatt(self._es)
        ]

    def fetch_data(self):
        result = [strategy.request() for strategy in self._strategies]
        return list(itertools.chain(*result))