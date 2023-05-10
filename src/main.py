from dotenv import load_dotenv
from misp import MISP
from tpot_elastic import TPotElastic

import os


if __name__ == '__main__':
    # This should not be available in a production version
    load_dotenv()

    # Get the user credentials in a save manner of TPOT Elasticsearch
    elastic_user = os.environ['ELASTIC_USER']
    elastic_pwd = os.environ['ELASTIC_PASSWORD']
    elastic_url = 'https://20.26.120.58:64297/es'

    # Creation of Elasticsearch client
    es = TPotElastic(elastic_url, elastic_user, elastic_pwd)
    
    # Get the user credentials of MISP instance
    misp_api_key = os.environ['MISP_API_KEY']
    misp_url = 'https://192.168.1.200'

    # Connect to MISP API Rest 
    misp = MISP(misp_url, misp_api_key)


