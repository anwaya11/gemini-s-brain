"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useRef, useState } from "react";

// Dynamically imported to avoid SSR canvas/window issues in Next.js
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-full text-neutral-500 text-xs font-mono">
      Initialising attack graph canvas…
    </div>
  ),
});

export interface GraphNode {
  id: string;
  name: string;
  type: string;
  [key: string]: any;
}

export interface GraphLink {
  source: string;
  target: string;
  type?: string;
  [key: string]: any;
}

export interface BlastRadiusGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
}

const NODE_COLORS: Record<string, string> = {
  attacker_ip: "#ef4444", // Red - threat actor
  target_host: "#3b82f6", // Blue/Indigo - target infrastructure
  decoy_honeypot: "#f59e0b", // Amber/Gold - decoy honeypot trap
  ip: "#f97316", // Orange
  hostname: "#6366f1", // Indigo
  user: "#a855f7", // Purple
  process: "#10b981", // Green
  file: "#ec4899", // Pink
  url: "#06b6d4", // Cyan
};

const LINK_COLORS: Record<string, string> = {
  targeted: "#ef4444cc",
  redirected_to: "#f59e0bcc",
  connected_to: "#3b82f6cc",
  spawned: "#10b981cc",
};

function getNodeColor(type: string): string {
  return NODE_COLORS[type] || "#94a3b8";
}

function getLinkColor(type?: string): string {
  if (!type) return "#ffffff33";
  return LINK_COLORS[type.toLowerCase()] || "#ffffff44";
}

export default function BlastRadiusGraph({ nodes, links }: BlastRadiusGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 600, height: 400 });

  useEffect(() => {
    if (!containerRef.current) return;
    const updateDims = () => {
      if (containerRef.current) {
        const { clientWidth, clientHeight } = containerRef.current;
        if (clientWidth > 0 && clientHeight > 0) {
          setDimensions({ width: clientWidth, height: clientHeight });
        }
      }
    };

    updateDims();
    const observer = new ResizeObserver(updateDims);
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const paintNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const color = getNodeColor(node.type);
      const label = (node.name || node.id || "") as string;
      const fontSize = Math.max(10 / globalScale, 3.5);

      // Node aura/halo
      ctx.beginPath();
      ctx.arc(node.x, node.y, 11, 0, 2 * Math.PI);
      ctx.fillStyle = color + "22";
      ctx.fill();

      // Node core
      ctx.beginPath();
      ctx.arc(node.x, node.y, 6, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();

      // Node border ring
      ctx.beginPath();
      ctx.arc(node.x, node.y, 7, 0, 2 * Math.PI);
      ctx.strokeStyle = color + "aa";
      ctx.lineWidth = 1.5 / globalScale;
      ctx.stroke();

      // Label text
      ctx.font = `600 ${fontSize}px monospace`;
      ctx.textAlign = "center";
      ctx.fillStyle = "#e2e8f0";
      ctx.fillText(label, node.x, node.y + 14 / globalScale);
    },
    []
  );

  return (
    <div ref={containerRef} className="w-full h-full min-h-[350px] relative overflow-hidden">
      <ForceGraph2D
        graphData={{ nodes, links }}
        backgroundColor="transparent"
        nodeCanvasObject={paintNode}
        nodeCanvasObjectMode={() => "replace"}
        linkColor={(link: any) => getLinkColor(link.type)}
        linkWidth={1.5}
        linkDirectionalArrowLength={6}
        linkDirectionalArrowRelPos={1}
        linkDirectionalParticles={2}
        linkDirectionalParticleWidth={1.8}
        linkDirectionalParticleSpeed={0.005}
        linkDirectionalParticleColor={(link: any) => getLinkColor(link.type)}
        linkLabel={(link: any) => link.type || "rel"}
        nodeLabel={(node: any) => `${node.name || node.id} (${node.type})`}
        cooldownTicks={100}
        width={dimensions.width}
        height={dimensions.height}
      />
    </div>
  );
}
