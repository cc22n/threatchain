from pydantic import BaseModel


class IocClassifyResponse(BaseModel):
    value: str
    type: str
    normalized: str
