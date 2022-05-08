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
        self.section_fields = ['name', 'size', 'type', 'alignment', 'offset', 'flags', 'flags_list',
                               'numberof_relocations', 'relocations', 'relocation_offset', 'entropy',
                               'virtual_address', 'reserved1', 'reserved2', 'reserved3', 'segment', 'content']
        logging.debug("MachOParser instance initialized")

    def get_basic_info(self):
        pass

    def print_sections(self, *argc, **argv):
        if len(argc) == 0:
            print(f"{'NAME':<15}{'OFFSET':<15}{'SIZE':<15}{'ENTROPY':<15}")
            for section in self.binary.sections:
                print(f"{section.name:<15}{section.offset:<15}{section.size:<15}{section.entropy:<15}")
        else:
            for _ in argc:
                section = self.binary.get_section(_)
                print(f"{'name':<25}", section.name)
                print(f"{'size':<25}", section.size)
                print(f"{'type':<25}", section.type)
                print(f"{'alignment':<25}", section.alignment)
                print(f"{'offset':<25}", section.offset)
                print(f"{'flags':<25}", section.flags)
                if section.flags != 0:
                    print(f"{'flags_list':<15}", section.flags_list)
                print(f"{'numberof_relocations':<25}", section.numberof_relocations)
                if section.numberof_relocations != 0:
                    for it in range(section.numberof_relocations):
                        print(f"{'relocations':<25}", section.relocations[it])
                    print(f"{'relocation_offset':<25}", section.relocation_offset)
                print(f"{'entropy':<25}", section.entropy)
                print(f"{'virtual_address':<25}", section.virtual_address)
                print(f"{'reserved1':<25}", section.reserved1)
                print(f"{'reserved2':<25}", section.reserved2)
                print(f"{'reserved3':<25}", section.reserved3)
                #print(f"{'segment':<15}", section.segment)
                # print(f"{'content':<15}", section.content)

    def get_hex(self):
        pass
