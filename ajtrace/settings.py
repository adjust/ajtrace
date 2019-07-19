import yaml

class GlobalConfig:
    __config = None

    def initialize(path):
        GlobalConfig.__config = yaml.load(open(path, 'r'))

    def get(key, default=None):
        return GlobalConfig.__config.get(key, default)

