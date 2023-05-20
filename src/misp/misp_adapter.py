from misp.misp import MISP


class MISPTPotAdapter(MISP):
    def __init__(self, misp_url, misp_api_key, tpot):
        self._tpot = tpot
        super().__init__(misp_url, misp_api_key)

    def parse(self, data: list):
        for event in data:
            event_id = self.add_new_event(event['type'])
            for tag in event:
                self.add_new_attribute_to_event(event_id, tag, event[tag])

    