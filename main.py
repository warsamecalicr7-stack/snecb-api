import csv
import io
import os
import re
import time
from typing import Optional
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field


# ============================================================
# CONFIGURATION
# ============================================================

SNECB_BASE_URL = "https://www.slnecb.org"
SNECB_RESULTS_URL = f"{SNECB_BASE_URL}/results"
SNECB_SEARCH_URL = f"{SNECB_BASE_URL}/results/search"

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))
REQUEST_DELAY_SECONDS = float(os.getenv("REQUEST_DELAY_SECONDS", "4"))

# Maximum number of IDs that /scan or /schools can check.
MAX_SCAN_SIZE = int(os.getenv("MAX_SCAN_SIZE", "500"))

# Optional API protection.
# If API_KEY is empty, authentication is disabled.
API_KEY = os.getenv("API_KEY", "").strip()


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="SNECB Verification API",
    description=(
        "API bridge for SNECB student verification and school-name lookup."
    ),
    version="2.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================
# MODELS
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
    subjects: list[SubjectResult] = Field(default_factory=list)


class ScanResult(BaseModel):
    checked: int
    found: int
    results: list[StudentResult]


class SchoolList(BaseModel):
    count: int
    schools: list[str]


# ============================================================
# API KEY
# ============================================================

def check_api_key(authorization: Optional[str]) -> None:
    """
    If API_KEY is configured on Render, require:

        Authorization: Bearer YOUR_API_KEY

    If API_KEY is empty, authentication is disabled.
    """

    if not API_KEY:
        return

    expected = f"Bearer {API_KEY}"

    if authorization != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid API authorization.",
        )


# ============================================================
# STUDENT NUMBER NORMALIZATION
# ============================================================

def normalize_student_number(student_number: str) -> str:
    value = re.sub(
        r"\s+",
        "",
        student_number.strip().upper(),
    )

    if len(value) < 5 or len(value) > 50:
        raise ValueError("Invalid student number length.")

    return value


# ============================================================
# CSRF
# ============================================================

def extract_csrf(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "html.parser")

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
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
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
            detail=f"Unable to connect to SNECB: {exc}",
        )

    csrf = extract_csrf(response.text)

    xsrf = session.cookies.get("XSRF-TOKEN")

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

    payload = {
        "student_number": student_number.lower(),
        "level": level,
    }

    try:
        response = session.post(
            SNECB_SEARCH_URL,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"SNECB search failed: {exc}",
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
                "Retry-After": retry,
            },
        )

    # --------------------------------------------------------
    # CSRF
    # --------------------------------------------------------

    if response.status_code == 419:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB CSRF/session validation failed."
            ),
        )

    # --------------------------------------------------------
    # FORBIDDEN
    # --------------------------------------------------------

    if response.status_code == 403:

        raise HTTPException(
            status_code=502,
            detail=(
                "SNECB rejected the verification request."
            ),
        )

    # --------------------------------------------------------
    # SERVER ERROR
    # --------------------------------------------------------

    if response.status_code >= 500:

        raise HTTPException(
            status_code=502,
            detail=(
                f"SNECB server error: "
                f"HTTP {response.status_code}."
            ),
        )

    # --------------------------------------------------------
    # OTHER HTTP ERROR
    # --------------------------------------------------------

    if response.status_code != 200:

        raise HTTPException(
            status_code=502,
            detail=(
                f"SNECB returned HTTP "
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
            detail="SNECB returned non-JSON data.",
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

    subjects = []

    for item in student.get("results", []):

        subjects.append(
            SubjectResult(
                subject=str(
                    item.get("subject", "")
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
        )

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
        name=student.get("name"),
        school=student.get("school"),
        level=student.get("level"),
        academic_year=student.get("acyear"),
        overall_grade=student.get("grade"),
        status=student.get("pass_fail_status"),
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
        "version": "2.0.0",
        "endpoints": {
            "verify": "/verify",
            "schools_json": "/schools/json",
            "schools_csv": "/schools/csv",
            "schools_default": "/schools",
            "scan": "/scan",
            "health": "/health",
            "docs": "/docs",
            "openapi": "/openapi.json",
        },
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "service": "SNECB Verification API",
        "version": "2.0.0",
    }


# ============================================================
# VERIFY
# ============================================================

@app.get(
    "/verify",
    response_model=StudentResult,
)
def verify(
    student_id: str = Query(
        ...,
        description=(
            "SNECB student number, "
            "for example A25S075/001"
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

    check_api_key(authorization)

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
# INTERNAL SCHOOL SCANNER
# ============================================================

def scan_school_names(
    prefix: str,
    start: int,
    end: int,
    suffix: str,
    level: str,
) -> tuple[int, list[str]]:

    if end < start:

        raise HTTPException(
            status_code=400,
            detail="end must be >= start.",
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

    schools = []

    seen = set()

    checked = 0

    for number in range(start, end + 1):

        student_id = (
            f"{prefix}"
            f"{number:03d}"
            f"{suffix}"
        )

        checked += 1

        try:

            result = search_snecb(
                student_id,
                level,
            )

            if result.found and result.school:

                school = result.school.strip()

                if school and school not in seen:

                    seen.add(school)
                    schools.append(school)

        except HTTPException as exc:

            # Never continue through a rate-limit response.
            if exc.status_code == 429:
                raise

            # For an individual failed lookup,
            # continue scanning the remaining IDs.
            continue

        # Delay between requests.
        if number < end:

            time.sleep(
                REQUEST_DELAY_SECONDS
            )

    return checked, schools


# ============================================================
# SCHOOLS JSON
# ============================================================

@app.get(
    "/schools/json",
    response_model=SchoolList,
)
def schools_json(
    prefix: str = Query(
        "A25S",
        description="Student number prefix.",
    ),
    start: int = Query(
        1,
        ge=1,
        description="First ID number.",
    ),
    end: int = Query(
        500,
        ge=1,
        description="Last ID number.",
    ),
    suffix: str = Query(
        "/001",
        description="Student number suffix.",
    ),
    level: str = Query(
        "",
        description="Optional SNECB level.",
    ),
    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(authorization)

    checked, schools = scan_school_names(
        prefix=prefix,
        start=start,
        end=end,
        suffix=suffix,
        level=level,
    )

    return SchoolList(
        count=len(schools),
        schools=schools,
    )


# ============================================================
# CSV CREATION
# ============================================================

def make_school_csv(
    schools: list[str],
) -> str:

    output = io.StringIO()

    writer = csv.writer(
        output,
        lineterminator="\n",
    )

    writer.writerow(
        ["School"]
    )

    for school in schools:

        writer.writerow(
            [school]
        )

    return output.getvalue()


# ============================================================
# SCHOOLS CSV
# ============================================================

@app.get(
    "/schools/csv",
    response_class=PlainTextResponse,
)
def schools_csv(
    prefix: str = Query(
        "A25S",
        description="Student number prefix.",
    ),
    start: int = Query(
        1,
        ge=1,
        description="First ID number.",
    ),
    end: int = Query(
        500,
        ge=1,
        description="Last ID number.",
    ),
    suffix: str = Query(
        "/001",
        description="Student number suffix.",
    ),
    level: str = Query(
        "",
        description="Optional SNECB level.",
    ),
    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(authorization)

    checked, schools = scan_school_names(
        prefix=prefix,
        start=start,
        end=end,
        suffix=suffix,
        level=level,
    )

    csv_data = make_school_csv(
        schools
    )

    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="snecb_schools.csv"'
            ),
            "X-Checked-IDs": str(checked),
            "X-Schools-Found": str(len(schools)),
        },
    )


# ============================================================
# DEFAULT /SCHOOLS
#
# Returns CSV so it can be opened by Excel/Google Sheets.
# ============================================================

@app.get(
    "/schools",
    response_class=PlainTextResponse,
)
def schools(
    prefix: str = Query(
        "A25S",
        description="Student number prefix.",
    ),
    start: int = Query(
        1,
        ge=1,
    ),
    end: int = Query(
        500,
        ge=1,
    ),
    suffix: str = Query(
        "/001",
    ),
    level: str = Query(
        "",
    ),
    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(authorization)

    checked, school_names = scan_school_names(
        prefix=prefix,
        start=start,
        end=end,
        suffix=suffix,
        level=level,
    )

    csv_data = make_school_csv(
        school_names
    )

    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="snecb_schools.csv"'
            ),
            "X-Checked-IDs": str(checked),
            "X-Schools-Found": str(
                len(school_names)
            ),
        },
    )


# ============================================================
# FULL STUDENT SCAN
# ============================================================

@app.get(
    "/scan",
    response_model=ScanResult,
)
def scan(
    prefix: str = Query(
        "A25S",
        description="Student number prefix.",
    ),
    start: int = Query(
        1,
        ge=1,
    ),
    end: int = Query(
        20,
        ge=1,
    ),
    suffix: str = Query(
        "/001",
    ),
    level: str = Query(
        "",
    ),
    authorization: Optional[str] = Header(
        default=None
    ),
):

    check_api_key(authorization)

    if end < start:

        raise HTTPException(
            status_code=400,
            detail="end must be >= start.",
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

    found_results = []

    checked = 0

    for number in range(start, end + 1):

        student_id = (
            f"{prefix}"
            f"{number:03d}"
            f"{suffix}"
        )

        checked += 1

        try:

            result = search_snecb(
                student_id,
                level,
            )

            if result.found:

                found_results.append(
                    result
                )

        except HTTPException as exc:

            if exc.status_code == 429:
                raise

            continue

        if number < end:

            time.sleep(
                REQUEST_DELAY_SECONDS
            )

    return ScanResult(
        checked=checked,
        found=len(found_results),
        results=found_results,
    )
