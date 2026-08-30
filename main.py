@app.get(
    "/schools",
    response_model=list[str],
    operation_id="findSchoolNames",
)
def schools(
    prefix: str = Query("A25S"),
    start: int = Query(1, ge=1),
    end: int = Query(500, ge=1),
    suffix: str = Query("/001"),
    level: str = Query(""),
    authorization: Optional[str] = Header(default=None),
):
    check_api_key(authorization)

    if end < start:
        raise HTTPException(
            status_code=400,
            detail="end must be >= start",
        )

    total = end - start + 1

    if total > MAX_SCAN_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum scan size is {MAX_SCAN_SIZE} IDs.",
        )

    school_names = set()

    for number in range(start, end + 1):

        student_id = f"{prefix}{number:03d}{suffix}"

        try:
            result = search_snecb(student_id, level)

            if result.found and result.school:
                school_names.add(result.school.strip())

        except HTTPException as exc:
            if exc.status_code == 429:
                raise

        if number < end:
            time.sleep(REQUEST_DELAY_SECONDS)

    return sorted(
        school_names,
        key=lambda x: x.casefold()
    )
