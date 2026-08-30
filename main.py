import os
import re
import time
from typing import Optional
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# CONFIGURATION
# ============================================================

SNECB_BASE_URL = "https://www.slnecb.org"
SNECB_RESULTS_URL = f"{SNECB_BASE_URL}/results"
SNECB_SEARCH_URL = f"{SNECB_BASE_URL}/results/search"

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))

# Delay between requests.
# Keep this at 4 seconds to reduce the chance of hitting
# SNECB's rate limit.
REQUEST_DELAY_SECONDS = float(
    os.getenv("REQUEST_DELAY_SECONDS", "4")
)

# Maximum number of student IDs in one request.
# 500 = A25S001/001 through A25S500/001.
MAX_SCAN_SIZE = int(
    os.getenv("MAX_SCAN_SIZE", "500")
)

# Optional API key.
# Leave API_KEY empty in Render if you want to use
# the endpoint without authentication.
API_KEY = os.getenv("API_KEY", "")


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="SNECB School Finder API",
    description=(
        "Returns unique school names found in the "
        "SNECB public results system."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================
# AUTHENTICATION
# ============================================================

def check_api_key(
    authorization: Optional[str],
) -> None:

    if not API_KEY:
        return

    expected = f"Bearer {API_KEY}"

    if authorization != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid API authorization.",
        )


# ============================================================
# NORMALIZE STUDENT NUMBER
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
# EXTRACT CSRF TOKEN
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
# CREATE SNECB SESSION
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
# LOOK UP ONE STUDENT
#
# IMPORTANT:
# The SNECB server returns the complete student record
# internally. We extract ONLY the school name and never
# return the student record from our API.
# ============================================================

def get_school(
    student_number: str,
    level: str = "",
) -> Optional[str]:

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
    # OTHER HTTP ERROR
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
    # PARSE JSON
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
    # EXTRACT STUDENT
    # --------------------------------------------------------

    student = (
        data.get("student")
        if data.get("success")
        else None
    )

    if not student:
        return None

    # --------------------------------------------------------
    # EXTRACT ONLY SCHOOL
    # --------------------------------------------------------

    school = student.get("school")

    if not school:
        return None

    school = str(school).strip()

    if not school:
        return None

    return school


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "SNECB School Finder API",
        "status": "online",
        "version": "2.0.0",
        "max_scan_size": MAX_SCAN_SIZE,
        "request_delay_seconds": REQUEST_DELAY_SECONDS,
        "endpoint": "/schools",
        "docs": "/docs",
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
# SCHOOLS ONLY
# ============================================================

@app.get(
    "/schools",
    response_model=list[str],
    operation_id="findSchoolNames",
)
def schools(

    prefix: str = Query(
        "A25S",
        description=(
            "Student number prefix. "
            "Example: A25S"
        ),
    ),

    start: int = Query(
        1,
        ge=1,
        description=(
            "First number to check."
        ),
    ),

    end: int = Query(
        500,
        ge=1,
        description=(
            "Last number to check."
        ),
    ),

    suffix: str = Query(
        "/001",
        description=(
            "Student number suffix. "
            "Example: /001"
        ),
    ),

    level: str = Query(
        "",
        description=(
            "Optional SNECB level."
        ),
    ),

    authorization: Optional[str] = Header(
        default=None
    ),
):

    # --------------------------------------------------------
    # CHECK AUTH
    # --------------------------------------------------------

    check_api_key(
        authorization
    )

    # --------------------------------------------------------
    # VALIDATE RANGE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # UNIQUE SCHOOL NAMES
    # --------------------------------------------------------

    school_names = set()

    # --------------------------------------------------------
    # CHECK STUDENT NUMBERS
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

            school = get_school(
                student_id,
                level,
            )

            if school:
                school_names.add(
                    school
                )

        except HTTPException as exc:

            # Stop if SNECB rate-limits us.
            if exc.status_code == 429:
                raise

            # For other individual errors,
            # continue with the next ID.
            continue

        # ----------------------------------------------------
        # DELAY
        # ----------------------------------------------------

        if number < end:

            time.sleep(
                REQUEST_DELAY_SECONDS
            )

    # --------------------------------------------------------
    # SORT SCHOOL NAMES
    # --------------------------------------------------------

    result = sorted(
        school_names,
        key=lambda name: name.casefold(),
    )

    # --------------------------------------------------------
    # RETURN SCHOOL NAMES ONLY
    # --------------------------------------------------------

    return result
