from ExecParser import logger
from ExecParser.parsers.pe_parser import PEParser, NotPEFormat
from ExecParser.parsers.macho_parser import MachOParser, NotMacOFormat
from ExecParser.parsers.abstract import UnknownFormat


ALL_PARSERS = [PEParser, MachOParser]


class CmdHelper(object):

    def __init__(self):
        self.my_parser = None

    def process(self, args):
        self.guess_filetype(args)
        logger.info(f"Assuming your file is a {self.my_parser.format}")

        if args.header:
            print(self.my_parser.get_header())

        elif args.sections:
            self.my_parser.print_sections()

        elif args.section_more:
            self.my_parser.print_sections(args.section_more)

    def guess_filetype(self, args):
        logger.debug("Determining executable file type.")
        for iter_parser in ALL_PARSERS:
            try:
                logger.debug(f"Trying {iter_parser}")
                self.my_parser = iter_parser(args.exec_file)
            except NotPEFormat:
                logger.debug(f"{args.exec_file} is not a PE")
                continue
            except NotMacOFormat:
                logger.debug(f"{args.exec_file} is not a Mach-O")
                continue
            except UnknownFormat:
                logger.error(f"{args.exec_file} is not executable")
                return None
            break
