import os
import re
import time
import csv
import io
from typing import Optional
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse


# ============================================================
# SNECB CONFIGURATION
# ============================================================

SNECB_BASE_URL = "https://www.slnecb.org"
SNECB_RESULTS_URL = f"{SNECB_BASE_URL}/results"
SNECB_SEARCH_URL = f"{SNECB_BASE_URL}/results/search"

REQUEST_TIMEOUT = int(
    os.getenv("REQUEST_TIMEOUT", "20")
)

REQUEST_DELAY_SECONDS = float(
    os.getenv("REQUEST_DELAY_SECONDS", "4")
)

# Maximum IDs allowed in one request.
# 500 means A25S001/001 -> A25S500/001
MAX_SCAN_SIZE = int(
    os.getenv("MAX_SCAN_SIZE", "500")
)

# Optional API key.
API_KEY = os.getenv("API_KEY", "")


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SNECB School CSV API",
    description=(
        "Finds school names from SNECB student numbers "
        "and returns them as a CSV spreadsheet."
    ),
    version="3.0.0",
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
# API KEY
# ============================================================

def check_api_key(
    authorization: Optional[str],
):
    if not API_KEY:
        return

    if authorization != f"Bearer {API_KEY}":
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
# CSRF TOKEN
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
        attrs={
            "name": "csrf-token"
        },
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
# GET ONE SCHOOL
#
# SNECB returns a complete student record internally.
# This function extracts ONLY the school name.
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
                "student_number": (
                    student_number.lower()
                ),
                "level": level,
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
        return None

    # --------------------------------------------------------
    # SCHOOL ONLY
    # --------------------------------------------------------

    school = student.get(
        "school"
    )

    if not school:
        return None

    school = str(
        school
    ).strip()

    if not school:
        return None

    return school


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "SNECB School CSV API",
        "status": "online",
        "version": "3.0.0",
        "endpoint": "/schools",
        "format": "CSV",
        "max_scan_size": MAX_SCAN_SIZE,
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
# SCHOOL CSV ENDPOINT
# ============================================================

@app.get(
    "/schools",
    operation_id="getSchoolsCSV",
    responses={
        200: {
            "description": "CSV spreadsheet containing school names only.",
            "content": {
                "text/csv": {}
            },
        }
    },
)
def schools(

    prefix: str = Query(
        "A25S",
        description="Student number prefix. Example: A25S",
    ),

    start: int = Query(
        1,
        ge=1,
        description="First student number.",
    ),

    end: int = Query(
        500,
        ge=1,
        description="Last student number.",
    ),

    suffix: str = Query(
        "/001",
        description="Student number suffix. Example: /001",
    ),

    level: str = Query(
        "",
        description="Optional SNECB level.",
    ),

    authorization: Optional[str] = Header(
        default=None
    ),
):

    # --------------------------------------------------------
    # AUTH
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
    # SCHOOL SET
    # --------------------------------------------------------

    school_names = set()

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

            school = get_school(
                student_id,
                level,
            )

            if school:
                school_names.add(
                    school
                )

        except HTTPException as exc:

            # Stop immediately on SNECB rate limit.
            if exc.status_code == 429:
                raise

            # Continue if one individual
            # lookup fails.
            continue

        # ----------------------------------------------------
        # DELAY
        # ----------------------------------------------------

        if number < end:

            time.sleep(
                REQUEST_DELAY_SECONDS
            )

    # --------------------------------------------------------
    # SORT
    # --------------------------------------------------------

    schools_sorted = sorted(
        school_names,
        key=lambda x: x.casefold(),
    )

    # --------------------------------------------------------
    # CREATE CSV
    # --------------------------------------------------------

    output = io.StringIO(
        newline=""
    )

    writer = csv.writer(
        output
    )

    # Header
    writer.writerow(
        ["School"]
    )

    # School names only
    for school in schools_sorted:

        writer.writerow(
            [school]
        )

    # --------------------------------------------------------
    # PREPARE FILE
    # --------------------------------------------------------

    csv_content = output.getvalue()

    output.close()

    filename = (
        f"snecb_schools_"
        f"{prefix}"
        f"{start:03d}-"
        f"{end:03d}.csv"
    )

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )
