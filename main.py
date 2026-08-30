import os
import re
import time
from typing import Optional
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

SNECB_BASE_URL = "https://www.slnecb.org"
SNECB_RESULTS_URL = f"{SNECB_BASE_URL}/results"
SNECB_SEARCH_URL = f"{SNECB_BASE_URL}/results/search"

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))

# Keep a delay between requests to avoid triggering SNECB's
# rate limiting.
REQUEST_DELAY_SECONDS = float(
    os.getenv("REQUEST_DELAY_SECONDS", "4")
)

# Maximum number of IDs that /scan and /schools can check.
# 500 allows A25S001/001 through A25S500/001.
MAX_SCAN_SIZE = int(
    os.getenv("MAX_SCAN_SIZE", "500")
)

# Optional API key.
# Leave empty in Render if you want Swagger to work without
# authentication.
API_KEY = os.getenv("API_KEY", "")


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="SNECB Verification API",
    description=(
        "API for verifying SNECB student result records and "
        "collecting unique school names from a controlled range."
    ),
    version="1.3.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================
# RESPONSE MODELS
# ============================================================

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
    subjects: list[SubjectResult] = Field(
        default_factory=list
    )


class SearchRequest(BaseModel):
    level: str = ""
    student_number: str = Field(
        ...,
        description="SNECB student number, e.g. A25S075/001",
    )


class ScanResult(BaseModel):
    checked: int
    found: int
    results: list[StudentResult]


class SchoolsResult(BaseModel):
    checked: int
    found_students: int
    school_count: int
    schools: list[str]


# ============================================================
# AUTHENTICATION
# ============================================================

def check_api_key(
    authorization: Optional[str],
) -> None:
    """
    If API_KEY is configured in Render, requests must contain:

    Authorization: Bearer YOUR_API_KEY

    If API_KEY is empty, authentication is disabled.
    """

    if API_KEY:
        expected = f"Bearer {API_KEY}"

        if authorization != expected:
            raise HTTPException(
                status_code=401,
                detail="Invalid API authorization.",
            )


# ============================================================
# STUDENT NUMBER
# ============================================================

def normalize_student_number(
    student_number: str,
) -> str:
    value = re.sub(
        r"\s+",
        "",
        student_number.strip().upper(),
    )

    if len(value) < 5 or len(value) > 50:
        raise ValueError(
            "Invalid student number length."
        )

    return value


# ============================================================
# CSRF
# ============================================================

def extract_csrf(
    html: str,
) -> Optional[str]:

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    meta = soup.find(
        "meta",
        attrs={"name": "csrf-token"},
    )

    if meta:
        return meta.get("content")

    return None


# ============================================================
# SNECB SESSION
# ============================================================

def create_session():

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/126.0.0.0 "
                "Safari/537.36"
            ),
            "Accept": (
                "text/html,"
                "application/xhtml+xml,"
                "application/xml;q=0.9,"
                "*/*;q=0.8"
            ),
        }
    )

    try:

        response = session.get(
            SNECB_RESULTS_URL,
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

    except requests.RequestException as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to connect to SNECB: "
                f"{exc}"
            ),
        )

    csrf = extract_csrf(
        response.text
    )

    xsrf = session.cookies.get(
        "XSRF-TOKEN"
    )

    return session, csrf, xsrf


# ============================================================
# SEARCH ONE STUDENT
# ============================================================

def search_snecb(
    student_number: str,
    level: str = "",
) -> StudentResult:

    student_number = normalize_student_number(
        student_number
    )

    session, csrf, xsrf = create_session()

    headers = {
        "Accept": (
            "application/json, "
            "text/plain, */*"
        ),
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": SNECB_BASE_URL,
        "Referer": SNECB_RESULTS_URL,
    }

    if csrf:
        headers["X-CSRF-TOKEN"] = csrf

    if xsrf:
        headers["X-XSRF-TOKEN"] = unquote(
            xsrf
        )

    try:

        response = session.post(
            SNECB_SEARCH_URL,
            json={
                "level": level,
                "student_number": (
                    student_number.lower()
                ),
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

    except requests.RequestException as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB search failed: "
                f"{exc}"
            ),
        )

    # --------------------------------------------------------
    # RATE LIMIT
    # --------------------------------------------------------

    if response.status_code == 429:

        retry = response.headers.get(
            "Retry-After",
            "60",
        )

        raise HTTPException(
            status_code=429,
            detail=(
                "SNECB rate limit reached. "
                f"Retry after {retry} seconds."
            ),
            headers={
                "Retry-After": retry
            },
        )

    # --------------------------------------------------------
    # CSRF
    # --------------------------------------------------------

    if response.status_code == 419:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB CSRF/session "
                "validation failed."
            ),
        )

    # --------------------------------------------------------
    # FORBIDDEN
    # --------------------------------------------------------

    if response.status_code == 403:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB rejected the "
                "verification request."
            ),
        )

    # --------------------------------------------------------
    # SERVER ERROR
    # --------------------------------------------------------

    if response.status_code >= 500:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB server error: "
                f"HTTP {response.status_code}."
            ),
        )

    # --------------------------------------------------------
    # OTHER ERROR
    # --------------------------------------------------------

    if response.status_code != 200:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB returned HTTP "
                f"{response.status_code}."
            ),
        )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    try:

        data = response.json()

    except ValueError:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB returned "
                "non-JSON data."
            ),
        )

    # --------------------------------------------------------
    # STUDENT
    # --------------------------------------------------------

    student = (
        data.get("student")
        if data.get("success")
        else None
    )

    if not student:

        return StudentResult(
            found=False,
            student_number=student_number,
        )

    # --------------------------------------------------------
    # SUBJECTS
    # --------------------------------------------------------

    subjects = [

        SubjectResult(
            subject=str(
                item.get(
                    "subject",
                    "",
                )
            ),
            grade=str(
                item.get(
                    "grade",
                    item.get(
                        "badge_grade",
                        "",
                    ),
                )
            ),
        )

        for item in student.get(
            "results",
            [],
        )
    ]

    # --------------------------------------------------------
    # RETURN
    # --------------------------------------------------------

    return StudentResult(

        found=True,

        student_number=str(
            student.get(
                "student_number",
                student_number,
            )
        ),

        name=student.get(
            "name"
        ),

        school=student.get(
            "school"
        ),

        level=student.get(
            "level"
        ),

        academic_year=student.get(
            "acyear"
        ),

        overall_grade=student.get(
            "grade"
        ),

        status=student.get(
            "pass_fail_status"
        ),

        subjects=subjects,
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "SNECB Verification API",
        "status": "online",
        "version": "1.3.0",
        "max_scan_size": MAX_SCAN_SIZE,
        "request_delay_seconds": REQUEST_DELAY_SECONDS,
        "docs": "/docs",
        "openapi": "/openapi.json",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "ok"
    }


# ============================================================
# VERIFY ONE STUDENT
# ============================================================

@app.get(
    "/verify",
    response_model=StudentResult,
    operation_id="verifyStudent",
)
def verify(

    student_id: str = Query(
        ...,
        description=(
            "SNECB student number, "
            "e.g. A25S075/001"
        ),
    ),

    level: str = Query(
        "",
        description="Optional SNECB level",
    ),

    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(
        authorization
    )

    try:

        return search_snecb(
            student_id,
            level,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# POST SEARCH
# ============================================================

@app.post(
    "/results/search",
    response_model=StudentResult,
    operation_id="searchSNECBResults",
)
def results_search(

    request: SearchRequest,

    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(
        authorization
    )

    try:

        return search_snecb(
            request.student_number,
            request.level,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# FULL SCAN
# ============================================================

@app.get(
    "/scan",
    response_model=ScanResult,
    operation_id="scanStudentNumbers",
)
def scan(

    prefix: str = Query(
        "A25S",
        description="Student number prefix",
    ),

    start: int = Query(
        1,
        ge=1,
        description="First numeric ID",
    ),

    end: int = Query(
        20,
        ge=1,
        description="Last numeric ID",
    ),

    suffix: str = Query(
        "/001",
        description="Student number suffix",
    ),

    level: str = Query(
        "",
        description="Optional SNECB level",
    ),

    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(
        authorization
    )

    if end < start:

        raise HTTPException(
            status_code=400,
            detail="end must be >= start",
        )

    total = end - start + 1

    if total > MAX_SCAN_SIZE:

        raise HTTPException(
            status_code=400,
            detail=(
                f"Maximum scan size is "
                f"{MAX_SCAN_SIZE} IDs."
            ),
        )

    found = []

    for number in range(
        start,
        end + 1,
    ):

        student_id = (
            f"{prefix}"
            f"{number:03d}"
            f"{suffix}"
        )

        result = search_snecb(
            student_id,
            level,
        )

        if result.found:
            found.append(
                result
            )

        if number < end:
            time.sleep(
                REQUEST_DELAY_SECONDS
            )

    return ScanResult(

        checked=total,

        found=len(found),

        results=found,
    )


# ============================================================
# SCHOOLS ONLY
# ============================================================

@app.get(
    "/schools",
    response_model=SchoolsResult,
    operation_id="findSchools",
)
def schools(

    prefix: str = Query(
        "A25S",
        description=(
            "Student number prefix, "
            "e.g. A25S"
        ),
    ),

    start: int = Query(
        1,
        ge=1,
        description=(
            "First numeric ID"
        ),
    ),

    end: int = Query(
        500,
        ge=1,
        description=(
            "Last numeric ID"
        ),
    ),

    suffix: str = Query(
        "/001",
        description=(
            "Student number suffix"
        ),
    ),

    level: str = Query(
        "",
        description=(
            "Optional SNECB level"
        ),
    ),

    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(
        authorization
    )

    # --------------------------------------------------------
    # VALIDATE RANGE
    # --------------------------------------------------------

    if end < start:

        raise HTTPException(
            status_code=400,
            detail="end must be >= start",
        )

    total = end - start + 1

    if total > MAX_SCAN_SIZE:

        raise HTTPException(
            status_code=400,
            detail=(
                f"Maximum scan size is "
                f"{MAX_SCAN_SIZE} IDs."
            ),
        )

    # --------------------------------------------------------
    # UNIQUE SCHOOL SET
    # --------------------------------------------------------

    school_names = set()

    found_students = 0

    # --------------------------------------------------------
    # SCAN
    # --------------------------------------------------------

    for number in range(
        start,
        end + 1,
    ):

        student_id = (
            f"{prefix}"
            f"{number:03d}"
            f"{suffix}"
        )

        try:

            result = search_snecb(
                student_id,
                level,
            )

        except HTTPException as exc:

            # Stop immediately if SNECB tells
            # us that the rate limit has been hit.
            if exc.status_code == 429:
                raise

            # For another failed individual
            # lookup, continue to the next ID.
            result = StudentResult(
                found=False,
                student_number=student_id,
            )

        # ----------------------------------------------------
        # SCHOOL FOUND
        # ----------------------------------------------------

        if result.found:

            found_students += 1

            if result.school:

                school = result.school.strip()

                if school:

                    school_names.add(
                        school
                    )

        # ----------------------------------------------------
        # DELAY
        # ----------------------------------------------------

        if number < end:

            time.sleep(
                REQUEST_DELAY_SECONDS
            )

    # --------------------------------------------------------
    # SORT SCHOOLS
    # --------------------------------------------------------

    schools_sorted = sorted(
        school_names,
        key=lambda x: x.casefold(),
    )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return SchoolsResult(

        checked=total,

        found_students=found_students,

        school_count=len(
            schools_sorted
        ),

        schools=schools_sorted,
    )
