from pydantic import BaseModel, Field


class IOC(BaseModel):

    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    malware: list[str] = Field(default_factory=list)