import json

import yaml


class AbstractFormatter:
    @staticmethod
    def to_json(data: dict) -> str:
        return json.dumps(data, indent=2)

    @staticmethod
    def to_yaml(data: dict) -> str:
        return yaml.safe_dump(data, sort_keys=False)
