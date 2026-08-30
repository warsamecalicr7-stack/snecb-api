import os
import re
import time
from typing import Optional
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

SNECB_BASE_URL = "https://www.slnecb.org"
SNECB_RESULTS_URL = f"{SNECB_BASE_URL}/results"
SNECB_SEARCH_URL = f"{SNECB_BASE_URL}/results/search"

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))
REQUEST_DELAY_SECONDS = float(os.getenv("REQUEST_DELAY_SECONDS", "4"))
MAX_SCAN_SIZE = int(os.getenv("MAX_SCAN_SIZE", "20"))
API_KEY = os.getenv("API_KEY", "")

app = FastAPI(title="SNECB Verification API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

class SubjectResult(BaseModel):
    subject: str
    grade: str

class StudentResult(BaseModel):
    found: bool
    student_number: str
    name: Optional[str] = None
    school: Optional[str] = None
    level: Optional[str] = None
    academic_year: Optional[str] = None
    overall_grade: Optional[str] = None
    status: Optional[str] = None
    subjects: list[SubjectResult] = []

class ScanResult(BaseModel):
    checked: int
    found: int
    results: list[StudentResult]

def check_api_key(authorization: Optional[str]):
    if not API_KEY:
        return
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(status_code=401, detail="Invalid API authorization.")

def normalize_student_number(student_number: str) -> str:
    value = re.sub(r"\s+", "", student_number.strip().upper())
    if len(value) < 5 or len(value) > 50:
        raise ValueError("Invalid student number length.")
    return value

def extract_csrf(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", attrs={"name": "csrf-token"})
    return meta.get("content") if meta else None

def create_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    try:
        r = session.get(SNECB_RESULTS_URL, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Unable to connect to SNECB: {exc}")
    return session, extract_csrf(r.text), session.cookies.get("XSRF-TOKEN")

def search_snecb(student_number: str, level: str = "") -> StudentResult:
    student_number = normalize_student_number(student_number)
    session, csrf, xsrf = create_session()

    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": SNECB_BASE_URL,
        "Referer": SNECB_RESULTS_URL,
    }
    if csrf:
        headers["X-CSRF-TOKEN"] = csrf
    if xsrf:
        headers["X-XSRF-TOKEN"] = unquote(xsrf)

    try:
        r = session.post(
            SNECB_SEARCH_URL,
            json={"student_number": student_number.lower(), "level": level},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"SNECB search failed: {exc}")

    if r.status_code == 429:
        retry = r.headers.get("Retry-After", "60")
        raise HTTPException(
            status_code=429,
            detail=f"SNECB rate limit reached. Retry after {retry} seconds.",
            headers={"Retry-After": retry},
        )
    if r.status_code == 419:
        raise HTTPException(status_code=502, detail="SNECB CSRF/session validation failed.")
    if r.status_code == 403:
        raise HTTPException(status_code=502, detail="SNECB rejected the verification request.")
    if r.status_code >= 500:
        raise HTTPException(status_code=502, detail=f"SNECB server error: HTTP {r.status_code}.")
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"SNECB returned HTTP {r.status_code}.")

    try:
        data = r.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="SNECB returned non-JSON data.")

    student = data.get("student") if data.get("success") else None
    if not student:
        return StudentResult(found=False, student_number=student_number)

    subjects = [
        SubjectResult(
            subject=str(x.get("subject", "")),
            grade=str(x.get("grade", x.get("badge_grade", ""))),
        )
        for x in student.get("results", [])
    ]

    return StudentResult(
        found=True,
        student_number=str(student.get("student_number", student_number)),
        name=student.get("name"),
        school=student.get("school"),
        level=student.get("level"),
        academic_year=student.get("acyear"),
        overall_grade=student.get("grade"),
        status=student.get("pass_fail_status"),
        subjects=subjects,
    )

@app.get("/")
def root():
    return {"service": "SNECB Verification API", "status": "online", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/verify", response_model=StudentResult)
def verify(
    student_id: str = Query(..., description="SNECB roll/index number, e.g. A25S075/001"),
    level: str = Query("", description="Optional SNECB level"),
    authorization: Optional[str] = Header(default=None),
):
    check_api_key(authorization)
    try:
        return search_snecb(student_id, level)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.get("/scan", response_model=ScanResult)
def scan(
    prefix: str = Query("A25S"),
    start: int = Query(1, ge=1),
    end: int = Query(20, ge=1),
    suffix: str = Query("/001"),
    level: str = Query(""),
    authorization: Optional[str] = Header(default=None),
):
    check_api_key(authorization)
    if end < start:
        raise HTTPException(status_code=400, detail="end must be >= start")
    total = end - start + 1
    max_scan = int(os.getenv("MAX_SCAN_SIZE", "20"))
    if total > max_scan:
        raise HTTPException(status_code=400, detail=f"Maximum scan size is {max_scan} IDs.")

    found = []
    for number in range(start, end + 1):
        sid = f"{prefix}{number:03d}{suffix}"
        try:
            result = search_snecb(sid, level)
            if result.found:
                found.append(result)
        except HTTPException as exc:
            if exc.status_code == 429:
                raise
        if number < end:
            time.sleep(float(os.getenv("REQUEST_DELAY_SECONDS", "4")))

    return ScanResult(checked=total, found=len(found), results=found)
