import pytest
from app.chains.ioc_classifier import IocClassifier, classify_ioc

def test_classify_valid_ipv4():
    assert classify_ioc("192.168.1.1") == "ip"
    assert classify_ioc("8.8.8.8") == "ip"

def test_classify_invalid_ip():
    assert classify_ioc("999.999.999.999") != "ip"

def test_classify_domains():
    assert classify_ioc("test.example.com") == "domain"

def test_classify_urls():
    assert classify_ioc("https://example.com/index.html") == "url"

def test_classify_cve():
    assert classify_ioc("CVE-2024-1234") == "cve"

def test_ioc_classifier_class():
    classifier = IocClassifier()
    res = classifier.classify("  8.8.8.8  ")
    assert res["type"] == "ip"
