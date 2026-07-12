import xml.etree.ElementTree as ET

import pytest

from scanners.sitemap_checker import _local_name, _parse_sitemap_xml


def test_local_name_strips_namespace():
    assert _local_name("{http://www.sitemaps.org/schemas/sitemap/0.9}urlset") == "urlset"


def test_local_name_no_namespace_unchanged():
    assert _local_name("urlset") == "urlset"


def test_parse_urlset_extracts_locations():
    xml_text = """<?xml version="1.0"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/a</loc></url>
      <url><loc>https://example.com/b</loc></url>
    </urlset>"""
    kind, locations = _parse_sitemap_xml(xml_text)
    assert kind == "urlset"
    assert locations == ["https://example.com/a", "https://example.com/b"]


def test_parse_sitemap_index_extracts_child_sitemaps():
    xml_text = """<?xml version="1.0"?>
    <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap><loc>https://example.com/sitemap1.xml</loc></sitemap>
      <sitemap><loc>https://example.com/sitemap2.xml</loc></sitemap>
    </sitemapindex>"""
    kind, locations = _parse_sitemap_xml(xml_text)
    assert kind == "index"
    assert len(locations) == 2


def test_parse_unknown_root_returns_empty():
    xml_text = "<somethingelse></somethingelse>"
    kind, locations = _parse_sitemap_xml(xml_text)
    assert kind == "unknown"
    assert locations == []


def test_parse_invalid_xml_raises_parse_error():
    with pytest.raises(ET.ParseError):
        _parse_sitemap_xml("<not valid xml")


def test_parse_urlset_ignores_entries_without_loc():
    xml_text = """<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><lastmod>2024-01-01</lastmod></url>
      <url><loc>https://example.com/only-this</loc></url>
    </urlset>"""
    kind, locations = _parse_sitemap_xml(xml_text)
    assert locations == ["https://example.com/only-this"]
