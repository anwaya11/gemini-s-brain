"""
backend/routers/graph.py
-------------------------
Attack Graph Router for Chimera SOC.

Builds GraphNode / GraphEdge records linked to an incident and exposes
a GET endpoint that returns data formatted for react-force-graph.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import GraphEdge, GraphNode

router = APIRouter(prefix="/api", tags=["Graph"])


# ---------------------------------------------------------------------------
# Helper – build the incident attack graph in the database
# ---------------------------------------------------------------------------

def create_incident_graph(
    db: Session,
    incident_id: int,
    source_ip: str,
    target_host: str = "web-prod-01",
    decoy_used: bool = False,
) -> dict:
    """
    Materialise a three-node attack graph for an incident:

        attacker_ip  ──targeted──►  target_host  ──redirected_to──►  decoy_honeypot (optional)

    All nodes and edges are persisted via SQLAlchemy and linked to *incident_id*.

    Returns:
        dict: {"nodes": [...], "links": [...]} ready for react-force-graph.
    """
    created_nodes: list[GraphNode] = []
    created_edges: list[GraphEdge] = []

    # --- Node: attacker IP ---
    attacker_node = GraphNode(
        node_type="attacker_ip",
        label=source_ip,
        properties={"role": "threat_actor", "source_ip": source_ip},
        incident_id=incident_id,
    )
    db.add(attacker_node)
    db.flush()  # get PK before creating edges
    created_nodes.append(attacker_node)

    # --- Node: target host ---
    target_node = GraphNode(
        node_type="target_host",
        label=target_host,
        properties={"role": "target", "hostname": target_host},
        incident_id=incident_id,
    )
    db.add(target_node)
    db.flush()
    created_nodes.append(target_node)

    # --- Edge: attacker → target ---
    edge_attack = GraphEdge(
        source_id=attacker_node.id,
        target_id=target_node.id,
        relation_type="targeted",
        properties={"confidence": "high"},
    )
    db.add(edge_attack)
    created_edges.append(edge_attack)

    # --- Optional decoy honeypot node + redirect edge ---
    if decoy_used:
        decoy_node = GraphNode(
            node_type="decoy_honeypot",
            label="decoy-login-trap",
            properties={"role": "honeypot", "deception": True},
            incident_id=incident_id,
        )
        db.add(decoy_node)
        db.flush()
        created_nodes.append(decoy_node)

        edge_redirect = GraphEdge(
            source_id=target_node.id,
            target_id=decoy_node.id,
            relation_type="redirected_to",
            properties={"mechanism": "deception_layer"},
        )
        db.add(edge_redirect)
        created_edges.append(edge_redirect)

    db.commit()
    for node in created_nodes:
        db.refresh(node)
    for edge in created_edges:
        db.refresh(edge)

    return _serialize_graph(created_nodes, created_edges)


def _serialize_graph(nodes: list, edges: list) -> dict:
    """Serialize nodes and edges into react-force-graph format."""
    return {
        "nodes": [
            {"id": str(n.id), "name": n.label, "type": n.node_type}
            for n in nodes
        ],
        "links": [
            {
                "source": str(e.source_id),
                "target": str(e.target_id),
                "type": e.relation_type,
            }
            for e in edges
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/graph/{incident_id}
# ---------------------------------------------------------------------------

@router.get(
    "/graph/{incident_id}",
    summary="Fetch attack graph for an incident",
    response_description="react-force-graph compatible nodes and links",
)
async def get_incident_graph(
    incident_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """
    Return all GraphNode and GraphEdge records for the given incident,
    serialised as react-force-graph-compatible JSON:

        {
          "nodes": [{"id": "...", "name": "...", "type": "..."}],
          "links": [{"source": "...", "target": "...", "type": "..."}]
        }
    """
    nodes = (
        db.query(GraphNode)
        .filter(GraphNode.incident_id == incident_id)
        .all()
    )

    if not nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No graph data found for incident {incident_id}.",
        )

    node_ids = {n.id for n in nodes}
    edges = (
        db.query(GraphEdge)
        .filter(
            GraphEdge.source_id.in_(node_ids),
            GraphEdge.target_id.in_(node_ids),
        )
        .all()
    )

    return _serialize_graph(nodes, edges)
