import lief
import logging
import ExecParser.parsers.abstract as abstract


class NotMacOFormat(TypeError):
    pass


class MachOParser(abstract.AbstractExecutable):

    def __new__(cls, exec_file: object) -> object:
        if lief.EXE_FORMATS.MACHO != lief.parse(exec_file).format:
            raise NotMacOFormat(exec_file)
        if not cls._instance:
            cls._instance = object.__new__(cls)
            logging.debug("MachOParser instance created")
        return cls._instance

    def __init__(self, exec_file):
        super().__init__(exec_file)
        self.format = 'MACHO'
        logging.debug("MachOParser instance initialized")

    def get_basic_info(self):
        pass

    def get_hex(self):
        pass
