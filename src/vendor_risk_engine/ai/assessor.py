"""
AI compliance evidence verifier. Parses uploaded PDFs (SOC 2, ISO 27001) and cross-checks them against questionnaire requirements.
Uses a RAG (Retrieval-Augmented Generation) pipeline for token efficiency and high accuracy.
"""
import re
import math
import json
import aiohttp
import structlog
from pypdf import PdfReader
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel
from vendor_risk_engine.config import get_settings

logger = structlog.get_logger(__name__)

class VerificationResult(BaseModel):
    control_name: str
    is_present: bool
    evidence_quote: str
    page_number: int
    confidence_score: float

class AIAssessor:
    def __init__(self):
        self.settings = get_settings()
        # Define keywords for fallback rule-based matching and semantic query formulation
        self.control_keywords = {
            "MFA": [r"(?i)mfa", r"(?i)multi-factor authentication", r"(?i)two-factor authentication", r"(?i)2fa"],
            "Encryption": [r"(?i)encryption", r"(?i)encrypt", r"(?i)aes-256", r"(?i)tls 1\.[23]", r"(?i)at rest", r"(?i)in transit"],
            "Incident Response": [r"(?i)incident response", r"(?i)ir plan", r"(?i)incident handling", r"(?i)breach notification"],
            "Penetration Testing": [r"(?i)penetration test", r"(?i)pen test", r"(?i)vulnerability assessment", r"(?i)vulnerability scan"],
            "Backups": [r"(?i)backup", r"(?i)disaster recovery", r"(?i)business continuity", r"(?i)replication"]
        }

    def _extract_text_with_pages(self, pdf_path: Path) -> List[Dict]:
        """Extract text page-by-page from the PDF."""
        pages_content = []
        try:
            reader = PdfReader(pdf_path)
            for idx, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                if text.strip():
                    pages_content.append({"page_num": idx + 1, "text": text})
        except Exception as e:
            logger.error("pdf_extraction_failed", error=str(e), path=str(pdf_path))
        return pages_content

    def _chunk_document(self, pages: List[Dict], chunk_size: int = 800, overlap: int = 150) -> List[Dict]:
        """Split page contents into overlapping character-level chunks."""
        chunks = []
        chunk_id = 0
        for page in pages:
            text = page["text"]
            page_num = page["page_num"]
            start = 0
            while start < len(text):
                end = start + chunk_size
                chunk_text = text[start:end]
                # Try to break at a space to preserve words
                if end < len(text):
                    last_space = chunk_text.rfind(" ")
                    if last_space > chunk_size // 2:
                        end = start + last_space
                        chunk_text = text[start:end]
                
                chunks.append({
                    "chunk_id": chunk_id,
                    "page_num": page_num,
                    "text": chunk_text.strip()
                })
                chunk_id += 1
                start += chunk_size - overlap
        return chunks

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two float vectors."""
        dot_product = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(y * y for y in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot_product / (norm_a * norm_b)

    async def _get_openai_embeddings(self, session: aiohttp.ClientSession, api_key: str, texts: List[str]) -> List[List[float]]:
        """Fetch vector embeddings from OpenAI API."""
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "text-embedding-3-small",
            "input": texts
        }
        async with session.post("https://api.openai.com/v1/embeddings", json=payload, headers=headers, timeout=20) as resp:
            if resp.status == 200:
                res_data = await resp.json()
                sorted_data = sorted(res_data["data"], key=lambda x: x["index"])
                return [item["embedding"] for item in sorted_data]
            else:
                resp_text = await resp.text()
                raise Exception(f"OpenAI Embeddings API failed with status {resp.status}: {resp_text}")

    def _fallback_local_search(self, chunks: List[Dict], control_name: str) -> VerificationResult:
        """Fallback deterministic regex keyword scanner when no LLM key is configured."""
        patterns = self.control_keywords.get(control_name, [])
        for chunk in chunks:
            text = chunk["text"]
            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    # Extract surrounding context
                    start = max(0, match.start() - 100)
                    end = min(len(text), match.end() + 100)
                    snippet = text[start:end].replace("\n", " ").strip()
                    return VerificationResult(
                        control_name=control_name,
                        is_present=True,
                        evidence_quote=f"... {snippet} ...",
                        page_number=chunk["page_num"],
                        confidence_score=0.85
                    )
        
        return VerificationResult(
            control_name=control_name,
            is_present=False,
            evidence_quote="No matching controls located in the uploaded evidence document.",
            page_number=0,
            confidence_score=0.90
        )

    async def verify_evidence(self, pdf_path: Path, controls_to_check: List[str]) -> List[VerificationResult]:
        """
        Verify compliance evidence PDF against a list of required controls.
        Connects to LLM + embeddings if configured; otherwise, runs local regex audit.
        """
        pages = self._extract_text_with_pages(pdf_path)
        if not pages:
            return [
                VerificationResult(
                    control_name=ctrl,
                    is_present=False,
                    evidence_quote="Failed to extract text from the evidence PDF file.",
                    page_number=0,
                    confidence_score=0.0
                )
                for ctrl in controls_to_check
            ]

        # Chunk document to support large files without token limits
        chunks = self._chunk_document(pages)
        if not chunks:
            return [
                VerificationResult(
                    control_name=ctrl,
                    is_present=False,
                    evidence_quote="No text content located in the document.",
                    page_number=0,
                    confidence_score=0.0
                )
                for ctrl in controls_to_check
            ]

        openai_key = getattr(self.settings, "openai_api_key", None)
        if not openai_key:
            logger.info("running_local_regex_verification_fallback")
            return [self._fallback_local_search(chunks, ctrl) for ctrl in controls_to_check]

        # LLM RAG Pipeline
        results = []
        try:
            async with aiohttp.ClientSession() as session:
                # 1. Fetch embeddings for all document chunks (batched in sizes of 100)
                chunk_texts = [c["text"] for c in chunks]
                chunk_embeddings = []
                for i in range(0, len(chunk_texts), 100):
                    batch = chunk_texts[i:i+100]
                    batch_embeddings = await self._get_openai_embeddings(session, openai_key.get_secret_value(), batch)
                    chunk_embeddings.extend(batch_embeddings)

                # 2. Re-evaluate each control via semantic retrieval
                for ctrl in controls_to_check:
                    # Construct query from control name and keywords
                    clean_kws = [re.sub(r'\(\?i\)', '', kw).strip() for kw in self.control_keywords.get(ctrl, [])]
                    query_text = f"{ctrl}: " + ", ".join(clean_kws) if clean_kws else ctrl
                    
                    query_embeddings = await self._get_openai_embeddings(session, openai_key.get_secret_value(), [query_text])
                    query_embedding = query_embeddings[0]

                    # Compute similarities
                    scored_chunks = []
                    for idx, chunk in enumerate(chunks):
                        sim = self._cosine_similarity(query_embedding, chunk_embeddings[idx])
                        scored_chunks.append((sim, chunk))

                    # Retrieve top 3 chunks
                    scored_chunks.sort(key=lambda x: x[0], reverse=True)
                    top_chunks = [chunk for sim, chunk in scored_chunks[:3]]

                    # Synthesize context
                    context_str = "\n\n".join([f"[Source Page {c['page_num']}] {c['text']}" for c in top_chunks])

                    prompt = (
                        f"You are a professional security compliance auditor. Analyze the following document excerpts and determine if the required security control is met.\n\n"
                        f"Required Control: '{ctrl}'\n\n"
                        f"Excerpts:\n{context_str}\n\n"
                        f"Provide a structured response. Return JSON only with the following schema:\n"
                        f"{{\n"
                        f"  \"is_present\": true/false,\n"
                        f"  \"evidence_quote\": \"exact snippet from the text supporting your decision (or 'Not found' if false)\",\n"
                        f"  \"page_number\": page number containing the evidence (integer)\n"
                        f"}}\n"
                    )

                    headers = {
                        "Authorization": f"Bearer {openai_key.get_secret_value()}",
                        "Content-Type": "application/json"
                    }
                    payload = {
                        "model": "gpt-3.5-turbo",
                        "messages": [{"role": "user", "content": prompt}],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.0
                    }

                    async with session.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=20) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            content = data["choices"][0]["message"]["content"]
                            parsed = json.loads(content)
                            results.append(VerificationResult(
                                control_name=ctrl,
                                is_present=parsed.get("is_present", False),
                                evidence_quote=parsed.get("evidence_quote", "Not found"),
                                page_number=parsed.get("page_number", 0),
                                confidence_score=0.98
                            ))
                        else:
                            logger.warn("openai_llm_failed_falling_back_to_local", status=resp.status)
                            results.append(self._fallback_local_search(chunks, ctrl))
        except Exception as e:
            logger.error("llm_rag_failed_falling_back", error=str(e))
            return [self._fallback_local_search(chunks, ctrl) for ctrl in controls_to_check]

        return results
