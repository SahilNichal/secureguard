"""Sample vulnerable file: XPath Injection"""
from lxml import etree


def find_user_by_name(xml_tree, username):
    """Find user by name in XML — VULNERABLE to XPath injection."""
    result = xml_tree.xpath(f"//user[@name='{username}']")
    return result


def find_product(xml_tree, product_id):
    """Find product in XML catalog — VULNERABLE to XPath injection."""
    result = xml_tree.xpath("//product[@id='" + product_id + "']")
    return result
