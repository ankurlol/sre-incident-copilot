import os
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from config.settings import settings

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> bool:
    expected_key = os.getenv("API_KEY")
    # If no API_KEY configured, allow requests in dev mode
    if not expected_key:
        return True
    if api_key and api_key == expected_key:
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing X-API-Key header"
    )
