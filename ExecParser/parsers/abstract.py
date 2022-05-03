from abc import ABCMeta, abstractmethod


class AbstractExecutable(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def get_basic_info(self):
        pass

    @abstractmethod
    def get_hex(self):
        pass
