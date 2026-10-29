"""MCP Server – Full MCP Protocol implementation with sampling support (2025-06-18 spec)."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .registry import mcp_registry
from ..security.rbac import require_permission

logger = logging.getLogger(__name__)

mcp_router = APIRouter(prefix="/mcp", tags=["mcp"])


# ─── Request/Response Models ───────────────────────────────────────────────

class MCPCapabilities(BaseModel):
    """MCP server capabilities per 2025-06-18 spec."""
    resources: bool = True
    prompts: bool = True
    tools: bool = True
    sampling: bool = True


class ToolCallRequest(BaseModel):
    """Request to call an MCP tool."""
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolCallResponse(BaseModel):
    """Response from an MCP tool call."""
    content: List[Dict[str, Any]]
    is_error: bool = False
    metadata: Optional[Dict[str, Any]] = None


class SamplingRequest(BaseModel):
    """Request for MCP sampling (server-initiated LLM call)."""
    prompt: str
    context: Optional[Dict[str, Any]] = None
    model_preference: Optional[str] = None
    max_tokens: Optional[int] = None


class SamplingResponse(BaseModel):
    """Response from MCP sampling."""
    content: str
    model: str
    usage: Optional[Dict[str, int]] = None
    mcp_trace_id: str


class ResourceReadRequest(BaseModel):
    """Request to read an MCP resource."""
    uri: str
    parameters: Optional[Dict[str, Any]] = None


class PromptGetRequest(BaseModel):
    """Request to get an MCP prompt template."""
    name: str
    arguments: Optional[Dict[str, Any]] = None


class PromptGetResponse(BaseModel):
    """Response with MCP prompt template."""
    name: str
    template: str
    parameters: Optional[List[str]] = None


# ─── MCP Endpoints ─────────────────────────────────────────────────────────

@mcp_router.get("/capabilities", response_model=MCPCapabilities)
async def capabilities():
    """Get MCP server capabilities (discovery endpoint)."""
    caps = await mcp_registry.get_capabilities()
    return MCPCapabilities(**caps)


@mcp_router.get("/tools")
async def list_tools(tenant: str = Depends(require_permission("mcp:tools", "read"))):
    """List all available MCP tools for the current tenant."""
    tools = await mcp_registry.get_tools(tenant)
    return {"tools": tools, "count": len(tools)}


@mcp_router.post("/tools/{tool_name}/call", response_model=ToolCallResponse)
async def call_tool(
    tool_name: str,
    request: ToolCallRequest,
    tenant: str = Depends(require_permission(f"mcp:tool:{tool_name}", "execute")),
):
    """Call a registered MCP tool."""
    tool = await mcp_registry.get_tool(tool_name, tenant)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found for tenant")

    try:
        # Increment call counter
        await mcp_registry.increment_tool_calls(tool_name)

        # Execute tool handler
        result = await tool.handler(request.arguments)

        return ToolCallResponse(
            content=[{"type": "text", "text": str(result)}],
            is_error=False,
            metadata={"tool": tool_name, "tenant": tenant},
        )
    except Exception as e:
        logger.exception(f"Tool call failed: {tool_name}")
        return ToolCallResponse(
            content=[{"type": "text", "text": f"Error: {str(e)}"}],
            is_error=True,
            metadata={"tool": tool_name, "error": str(e)},
        )


@mcp_router.get("/resources")
async def list_resources(tenant: str = Depends(require_permission("mcp:resources", "read"))):
    """List all available MCP resources for the current tenant."""
    resources = await mcp_registry.get_resources(tenant)
    return {"resources": resources, "count": len(resources)}


@mcp_router.post("/resources/read")
async def read_resource(
    request: ResourceReadRequest,
    tenant: str = Depends(require_permission("mcp:resources", "read")),
):
    """Read an MCP resource by URI."""
    # Resource reading logic – in prod, fetch from storage
    return {
        "uri": request.uri,
        "content": f"Resource content for {request.uri}",
        "mime_type": "application/json",
    }


@mcp_router.get("/prompts")
async def list_prompts(tenant: str = Depends(require_permission("mcp:prompts", "read"))):
    """List all available MCP prompt templates."""
    prompts = await mcp_registry.get_prompts(tenant)
    return {"prompts": prompts, "count": len(prompts)}


@mcp_router.post("/prompts/get", response_model=PromptGetResponse)
async def get_prompt(
    request: PromptGetRequest,
    tenant: str = Depends(require_permission("mcp:prompts", "read")),
):
    """Get an MCP prompt template by name."""
    prompts = await mcp_registry.get_prompts(tenant)
    for prompt in prompts:
        if prompt["name"] == request.name:
            return PromptGetResponse(**prompt)
    raise HTTPException(status_code=404, detail=f"Prompt '{request.name}' not found")


@mcp_router.post("/sampling", response_model=SamplingResponse)
async def mcp_sampling(
    request: SamplingRequest,
    tenant: str = Depends(require_permission("mcp:sampling", "execute")),
):
    """
    MCP Sampling – Server-initiated LLM call per 2025-06-18 spec.

    In production, this would:
    1. Forward to configured LLM with user approval flow
    2. Include full tracing and audit logging
    3. Respect rate limits and quotas
    """
    import uuid
    import time

    trace_id = f"sampling-{uuid.uuid4().hex[:8]}"
    logger.info(f"MCP Sampling request: {trace_id} for tenant: {tenant}")

    # In production: forward to LLM with proper approval flow
    # Demo: simulate sampling response
    start_time = time.time()

    return SamplingResponse(
        content=f"Sampled response for: {request.prompt[:100]}...",
        model=request.model_preference or "gpt-4o",
        usage={
            "prompt_tokens": len(request.prompt.split()),
            "completion_tokens": 150,
            "total_tokens": len(request.prompt.split()) + 150,
            "latency_ms": int((time.time() - start_time) * 1000),
        },
        mcp_trace_id=trace_id,
    )
