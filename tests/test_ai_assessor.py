"""
Unit tests for the RAG-based AI Assessor.
Covers document chunking, vector similarity math, and fallback matching.
"""
import pytest
from vendor_risk_engine.ai.assessor import AIAssessor, VerificationResult


def test_cosine_similarity():
    assessor = AIAssessor()
    
    # 1. Identical vectors -> 1.0
    vec1 = [1.0, 0.0, 1.0]
    vec2 = [1.0, 0.0, 1.0]
    assert pytest.approx(assessor._cosine_similarity(vec1, vec2)) == 1.0

    # 2. Orthogonal vectors -> 0.0
    vec3 = [1.0, 0.0]
    vec4 = [0.0, 1.0]
    assert pytest.approx(assessor._cosine_similarity(vec3, vec4)) == 0.0

    # 3. Empty/zero vectors -> 0.0
    vec5 = [0.0, 0.0]
    vec6 = [1.0, 1.0]
    assert assessor._cosine_similarity(vec5, vec6) == 0.0


def test_document_chunking():
    assessor = AIAssessor()
    pages = [
        {"page_num": 1, "text": "This is page one text content that is quite long. " * 10},
        {"page_num": 2, "text": "This is page two text."}
    ]
    
    # Run chunker
    chunks = assessor._chunk_document(pages, chunk_size=100, overlap=20)
    
    assert len(chunks) > 0
    # Assert each chunk matches structured properties
    for c in chunks:
        assert "chunk_id" in c
        assert "page_num" in c
        assert "text" in c
        assert len(c["text"]) <= 100


def test_fallback_local_search():
    assessor = AIAssessor()
    chunks = [
        {"chunk_id": 0, "page_num": 1, "text": "Our corporate policy strictly mandates MFA (multi-factor authentication) for all logins."},
        {"chunk_id": 1, "page_num": 2, "text": "We store user files with aes-256 encryption at rest."}
    ]
    
    # 1. Test match for MFA
    res_mfa = assessor._fallback_local_search(chunks, "MFA")
    assert res_mfa.is_present is True
    assert res_mfa.page_number == 1
    assert "MFA" in res_mfa.evidence_quote
    
    # 2. Test match for Encryption
    res_enc = assessor._fallback_local_search(chunks, "Encryption")
    assert res_enc.is_present is True
    assert res_enc.page_number == 2
    assert "aes-256" in res_enc.evidence_quote
    
    # 3. Test no match
    res_none = assessor._fallback_local_search(chunks, "Incident Response")
    assert res_none.is_present is False
    assert res_none.page_number == 0
