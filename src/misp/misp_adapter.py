from misp.misp import MISP


class MISPTPotAdapter(MISP):
    def __init__(self, misp_url, misp_api_key, tpot):
        self._tpot = tpot
        super().__init__(misp_url, misp_api_key)

    def parse(self, data: list):
        for event in data:
            new_event = self.create_event(event['type'])
            attributes = [self.create_attribute(tag, event[tag]) for tag in event]
            for attr in attributes:
                new_event.add_attribute(attr)
            # self.save_event(new_event)

    