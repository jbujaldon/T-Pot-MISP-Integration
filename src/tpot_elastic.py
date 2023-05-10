from elasticsearch import Elasticsearch

class TPotElastic:
    def __init__(self, elastic_url, elastic_user, elastic_pwd):
        self._es = Elasticsearch(elastic_url, basic_auth=(elastic_user, elastic_pwd), verify_certs=False)