from dotenv import load_dotenv
from misp.misp_adapter import MISPTPotAdapter
from tpot.tpot_elastic import TPotElasticContext

import os


if __name__ == '__main__':
    # This should not be available in a production version
    load_dotenv()

    # Get the user credentials in a save manner of TPOT Elasticsearch
    elastic_user = os.environ['ELASTIC_USER']
    elastic_pwd = os.environ['ELASTIC_PASSWORD']
    elastic_url = os.environ['ELASTIC_URL']

    # Creation of Elasticsearch client
    tpot = TPotElasticContext(elastic_url, elastic_user, elastic_pwd)
    
    # Get the user credentials of MISP instance
    misp_api_key = os.environ['MISP_API_KEY']
    misp_url = os.environ['MISP_URL']

    # Connect T-Pot data with MISP
    adapter = MISPTPotAdapter(misp_url, misp_api_key, tpot)
    adapter.parse(tpot.fetch_data())


