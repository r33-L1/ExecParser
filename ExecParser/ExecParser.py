from abc import ABCMeta, abstractmethod


class AbstractParser(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def parse_header(self):
        pass

    @abstractmethod
    def get_meta_info(self):
        pass

    @abstractmethod
    def print_hex(self):
        pass