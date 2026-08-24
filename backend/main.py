"""
backend/main.py
---------------
Chimera SOC Platform – FastAPI Application Entry-point.

Responsibilities:
- Lifespan handler: initialise SQLAlchemy tables on startup.
- POST /api/ingest   – ingest telemetry, AI triage, risk engine, graph build, WS broadcast.
- POST /api/incidents/{incident_id}/approve – analyst approval + WS broadcast.
- GET  /health       – DB connectivity probe.
- GET  /             – service metadata.
"""

import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.database import Base, engine, get_db, check_db_connection
from db import models
from db.models import Event, Incident
from agents.triage_agent import analyze_security_event
from agents.risk_engine import compute_incident_risk
from routers.graph import router as graph_router, create_incident_graph
from routers.ws import router as ws_router, manager as ws_manager


# ---------------------------------------------------------------------------
# Lifespan – schema initialisation
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create all SQLAlchemy tables on startup (idempotent)."""
    try:
        models.Base.metadata.create_all(bind=engine)
        print("[chimera-soc] Database schema successfully initialized.")
    except Exception as exc:
        print(f"[chimera-soc] WARNING – schema init failed: {exc}")
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Chimera SOC Platform API",
    description=(
        "Autonomous Security Operations Center (SOC) Platform. "
        "Ingests security telemetry, runs real-time threat intel lookups, "
        "LLM-driven triage, risk-weighted autonomy, attack-graph correlation, "
        "and live WebSocket broadcasting."
    ),
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(graph_router)
app.include_router(ws_router)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class IngestPayload(BaseModel):
    """Incoming security telemetry event."""
    source_ip: str = Field(..., example="45.33.32.156")
    payload: Union[Dict[str, Any], str] = Field(
        ...,
        example={"path": "/admin/config.php", "method": "POST"},
    )
    source: Optional[str] = Field("telemetry_stream", example="edr_sensor_01")
    event_type: Optional[str] = Field("security_event", example="credential_access_attempt")
    severity: Optional[str] = Field("info", example="high")
    raw_data: Optional[Dict[str, Any]] = None
    parsed_data: Optional[Dict[str, Any]] = None
    # Graph options
    target_host: Optional[str] = Field("web-prod-01", example="web-prod-01")
    decoy_used: Optional[bool] = Field(False, example=False)
    # Risk engine options
    blast_radius_hosts: Optional[int] = Field(1, example=1)
    asset_criticality: Optional[float] = Field(0.8, example=0.8)


class IngestResponse(BaseModel):
    """Ingestion + triage + risk response."""
    status: str
    event_id: int
    incident_id: int
    # Triage
    threat_level: str
    confidence_score: float
    mitre_tactic: str
    mitre_technique: str
    cve_references: List[str]
    reasoning: str
    recommended_action: str
    # Risk engine
    risk_score: float
    autonomous_action: bool
    risk_status: str
    risk_action: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/", tags=["Meta"])
async def root():
    """Service identity."""
    return {
        "service": "Chimera SOC Platform",
        "version": "0.2.0",
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/health", tags=["Meta"])
async def health_check():
    """Live DB connectivity probe."""
    db_ok = check_db_connection()
    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "unreachable",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post(
    "/api/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_200_OK,
    tags=["Ingest"],
    summary="Ingest telemetry → AI triage → risk engine → graph → WS broadcast",
)
async def ingest_security_event(
    payload: IngestPayload,
    db: Session = Depends(get_db),
) -> IngestResponse:
    """
    Full autonomous SOC pipeline:
    1. Persist raw Event.
    2. AI triage via Groq / fallback heuristics.
    3. Risk-weighted autonomy decision.
    4. Build attack graph (GraphNode + GraphEdge records).
    5. Broadcast live JSON to /ws/console.
    6. Return structured triage + risk report.
    """
    try:
        # --- Normalise payload ---
        if isinstance(payload.payload, dict):
            payload_dict = payload.payload
            raw_log_str = json.dumps(payload.payload)
        else:
            payload_dict = {"content": str(payload.payload)}
            raw_log_str = str(payload.payload)

        # 1. Persist Event
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

        # 2. AI Triage
        triage_report = analyze_security_event(
            source_ip=payload.source_ip,
            payload=payload_dict,
        )

        threat_level     = str(triage_report.get("threat_level", "medium")).lower()
        confidence_score = float(triage_report.get("confidence_score", 0.5))
        mitre_tactic     = str(triage_report.get("mitre_tactic", "Discovery"))
        mitre_technique  = str(triage_report.get("mitre_technique", "Unknown"))
        cve_refs         = triage_report.get("cve_references", [])
        cve_str          = ", ".join(cve_refs) if cve_refs else "None"

        # 3. Risk Engine
        risk = compute_incident_risk(
            confidence=confidence_score,
            blast_radius_hosts=payload.blast_radius_hosts or 1,
            asset_criticality=payload.asset_criticality or 0.8,
        )

        # 4. Persist Incident (link Event)
        incident = Incident(
            title=f"[{risk['status'].upper()}] {mitre_tactic} — {mitre_technique}",
            description=(
                f"Threat Level: {threat_level.upper()}\n"
                f"Confidence:   {confidence_score}\n"
                f"Risk Score:   {risk['risk_score']}\n"
                f"Risk Action:  {risk['action']}\n\n"
                f"Reasoning:\n{triage_report.get('reasoning', '')}\n\n"
                f"Recommended Action:\n{triage_report.get('recommended_action', '')}\n\n"
                f"CVE References: {cve_str}"
            ),
            severity=threat_level,
            status=risk["status"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        event.incident_id = incident.id
        event.severity    = threat_level
        event.status      = "triaged"
        db.commit()
        db.refresh(event)

        # 5. Build Attack Graph
        graph_data = create_incident_graph(
            db=db,
            incident_id=incident.id,
            source_ip=payload.source_ip,
            target_host=payload.target_host or "web-prod-01",
            decoy_used=payload.decoy_used or False,
        )

        # 6. Broadcast over WebSocket
        ws_payload = {
            "type": "new_event",
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": event.id,
            "incident_id": incident.id,
            "source_ip": payload.source_ip,
            "threat_level": threat_level,
            "confidence_score": confidence_score,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "cve_references": cve_refs,
            "reasoning": triage_report.get("reasoning", ""),
            "recommended_action": triage_report.get("recommended_action", ""),
            "risk": risk,
            "graph": graph_data,
        }
        await ws_manager.broadcast(ws_payload)

        return IngestResponse(
            status="success",
            event_id=event.id,
            incident_id=incident.id,
            threat_level=threat_level,
            confidence_score=confidence_score,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            cve_references=cve_refs,
            reasoning=triage_report.get("reasoning", ""),
            recommended_action=triage_report.get("recommended_action", ""),
            risk_score=risk["risk_score"],
            autonomous_action=risk["autonomous_action"],
            risk_status=risk["status"],
            risk_action=risk["action"],
        )

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion pipeline failed: {exc}",
        )


@app.post(
    "/api/incidents/{incident_id}/approve",
    tags=["Incidents"],
    summary="Analyst approval – mark incident resolved and broadcast",
    status_code=status.HTTP_200_OK,
)
async def approve_incident(
    incident_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """
    Mark an incident as resolved by the lead analyst.
    Stamps human_approved_by, resolved_at, updates status to 'resolved',
    and broadcasts the approval event over WebSocket.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )

    now = datetime.utcnow()
    incident.human_approved_by = "lead_analyst"
    incident.resolved_at       = now
    incident.status            = "resolved"
    incident.updated_at        = now
    db.commit()
    db.refresh(incident)

    # Broadcast approval event
    ws_payload = {
        "type": "incident_approved",
        "timestamp": now.isoformat(),
        "incident_id": incident_id,
        "approved_by": "lead_analyst",
        "resolved_at": now.isoformat(),
        "status": "resolved",
    }
    await ws_manager.broadcast(ws_payload)

    return {
        "status": "resolved",
        "incident_id": incident_id,
        "approved_by": "lead_analyst",
        "resolved_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Dev entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
