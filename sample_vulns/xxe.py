"""Sample vulnerable file: XML External Entity (XXE)"""
from lxml import etree


def parse_xml_input(xml_string):
    """Parse XML input - VULNERABLE to XXE."""
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_string.encode(), parser)
    return tree


def parse_xml_file(filepath):
    """Parse an XML file - VULNERABLE to XXE."""
    tree = etree.parse(filepath)
    return tree.getroot()
