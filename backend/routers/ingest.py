"""
backend/routers/ingest.py
-------------------------
Telemetry ingestion router with AI Triage support.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import Event, Incident
from agents.triage_agent import analyze_security_event

router = APIRouter(prefix="/api", tags=["Ingest"])


class IngestEventPayload(BaseModel):
    source_ip: str = Field(..., example="185.220.101.5")
    payload: Union[Dict[str, Any], str] = Field(
        ..., example={"path": "/etc/passwd", "method": "GET"}
    )
    source: Optional[str] = Field("telemetry_stream", example="edr_sensor_01")
    event_type: Optional[str] = Field("security_event", example="process_creation")
    severity: Optional[str] = Field("info", example="high")
    raw_data: Optional[Dict[str, Any]] = None
    parsed_data: Optional[Dict[str, Any]] = None


@router.post("/ingest", status_code=status.HTTP_200_OK)
async def ingest_event(payload: IngestEventPayload, db: Session = Depends(get_db)):
    """
    Ingest a security telemetry event and run autonomous AI triage.
    """
    try:
        if isinstance(payload.payload, dict):
            payload_dict = payload.payload
            raw_log_str = json.dumps(payload.payload)
        else:
            payload_dict = {"content": str(payload.payload)}
            raw_log_str = str(payload.payload)

        event = Event(
            source_ip=payload.source_ip,
            raw_log=raw_log_str,
            raw_data=payload.raw_data or payload_dict,
            parsed_data=payload.parsed_data or payload_dict,
            source=payload.source or "telemetry_stream",
            event_type=payload.event_type or "security_event",
            severity=payload.severity or "info",
            status="processing",
            timestamp=datetime.utcnow(),
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        triage_report = analyze_security_event(
            source_ip=payload.source_ip,
            payload=payload_dict,
        )

        threat_level = str(triage_report.get("threat_level", "medium")).lower()
        mitre_tactic = str(triage_report.get("mitre_tactic", "Security Alert"))
        mitre_technique = str(triage_report.get("mitre_technique", "Unknown Technique"))
        cve_refs = triage_report.get("cve_references", [])
        cve_str = ", ".join(cve_refs) if cve_refs else "None"

        incident = Incident(
            title=f"Incident: {mitre_tactic} ({mitre_technique})",
            description=(
                f"Threat Level: {threat_level.upper()}\n"
                f"Confidence: {triage_report.get('confidence_score', 0.0)}\n\n"
                f"Reasoning:\n{triage_report.get('reasoning', '')}\n\n"
                f"Recommended Action:\n{triage_report.get('recommended_action', '')}\n\n"
                f"CVE References: {cve_str}"
            ),
            severity=threat_level,
            status="open",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        event.incident_id = incident.id
        event.severity = threat_level
        event.status = "triaged"
        db.commit()
        db.refresh(event)

        return {
            "status": "success",
            "event_id": event.id,
            "incident_id": incident.id,
            **triage_report,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest event: {str(e)}",
        )
