from abc import ABCMeta, abstractmethod
import lief


class UnknownFormat(TypeError):
    pass


class AbstractExecutable(object):
    __metaclass__ = ABCMeta

    _instance = None

    def __new__(cls, exec_file):
        if lief.EXE_FORMATS.UNKNOWN == lief.parse(exec_file).format:
            raise UnknownFormat(exec_file)

    def __init__(self, exec_file):
        self.binary = lief.parse(exec_file)

    @abstractmethod
    def get_basic_info(self):
        pass

    def get_header(self):
        return self.binary.header

    def print_sections(self, *argc, **argv,):
        pass

    @abstractmethod
    def get_hex(self):
        pass
