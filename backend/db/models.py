from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    func
)
from sqlalchemy.orm import relationship
from db.database import Base  # re-exported from session.py via database.py shim


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default="medium", index=True)  # critical, high, medium, low, info
    status = Column(String(50), default="open", index=True)      # open, investigating, contained, resolved, closed
    assigned_to = Column(String(100), nullable=True)
    human_approved_by = Column(String(100), nullable=True)              # Analyst who approved the incident
    resolved_at = Column(DateTime(timezone=True), nullable=True)        # Timestamp of analyst approval / resolution
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    events = relationship("Event", back_populates="incident", cascade="all, delete-orphan")
    nodes = relationship("GraphNode", back_populates="incident")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    # Source identification
    source = Column(String(100), nullable=True, index=True)        # e.g., sysmon, edr, firewall, auth, zeek
    source_ip = Column(String(45), nullable=True, index=True)      # IPv4 or IPv6 address of the originating host

    # Event classification
    event_type = Column(String(100), nullable=True, index=True)    # e.g., process_creation, network_conn, failed_login
    severity = Column(String(50), default="info", index=True)      # critical, high, medium, low, info
    status = Column(String(50), default="pending", index=True)     # pending, processing, resolved, suppressed

    # Payload storage
    raw_log = Column(Text, nullable=True)                          # Raw log / payload string exactly as received
    raw_data = Column(JSON, nullable=True)                         # Original raw event/log payload (structured)
    parsed_data = Column(JSON, nullable=True)                      # Structured parsed fields

    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, server_default=func.now())

    # Relationships
    incident = relationship("Incident", back_populates="events")


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id = Column(Integer, primary_key=True, index=True)
    node_type = Column(String(50), nullable=False, index=True)     # e.g., ip, hostname, user, process, file, url, hash
    label = Column(String(255), nullable=False, index=True)        # Value/Identifier (e.g. 192.168.1.10, admin, cmd.exe)
    properties = Column(JSON, default=dict)                        # Extra metadata & attributes
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, server_default=func.now())

    # Relationships
    incident = relationship("Incident", back_populates="nodes")
    out_edges = relationship(
        "GraphEdge",
        foreign_keys="[GraphEdge.source_id]",
        back_populates="source_node",
        cascade="all, delete-orphan"
    )
    in_edges = relationship(
        "GraphEdge",
        foreign_keys="[GraphEdge.target_id]",
        back_populates="target_node",
        cascade="all, delete-orphan"
    )


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    relation_type = Column(String(100), nullable=False, index=True)  # e.g., CONNECTED_TO, SPAWNED, AUTHENTICATED_AS
    properties = Column(JSON, default=dict)                          # Extra relationship metadata (timestamp, port, etc.)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, server_default=func.now())

    # Relationships
    source_node = relationship("GraphNode", foreign_keys=[source_id], back_populates="out_edges")
    target_node = relationship("GraphNode", foreign_keys=[target_id], back_populates="in_edges")
