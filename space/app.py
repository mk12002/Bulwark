"""Gradio front end for the Bulwark Space.

Deliberately thin — all presentation logic lives in ``bulwark_demo.py`` so it can be
tested without Gradio installed. This file is layout only.

The agent audit is the first tab on purpose: it needs no upload, runs instantly, and
demonstrates the thing that makes Bulwark different from a file scanner — risk that only
exists because of how components were wired together.
"""

from __future__ import annotations

import gradio as gr

from bulwark_demo import (
    EXAMPLE_ASSISTANT,
    EXAMPLE_CLEAN,
    EXAMPLE_DEVOPS,
    EXAMPLE_TRIFECTA,
    audit_agent,
    recommend_agent,
    scan_model,
)

INTRO = """
# 🛡️ Bulwark — security for the AI agent supply chain

An AI agent is assembled from parts you didn't write: a model off the Hub, an MCP server
from a gist, a pile of tools wired into an autonomous loop. Each is a trust boundary — and
a system built entirely from *individually benign* parts can still be dangerous because of
**how they're wired together**.

Bulwark audits that at three levels. This Space demos two of them.

[GitHub](https://github.com/mk12002/Bulwark) ·
[Docs](https://mk12002.github.io/Bulwark/) ·
[Validation](https://github.com/mk12002/Bulwark/blob/main/docs/EMPIRICAL_VALIDATION.md)
"""

AGENT_BLURB = """
### ⚖️ Warden — scan the assembly

Paste an agent config. Warden normalizes it into one internal shape — it accepts its own
manifest YAML, an **OpenAI Assistants** payload, a **CrewAI** `agents.yaml`, or an
`.mcp.json` — then builds a capability graph and looks for **source → sink reachability**.

A tool that reads secrets is fine. A tool that sends HTTP is fine. Both in one agent is an
exfiltration path neither has alone, and if the agent *also* reads untrusted content, an
attacker can trigger it by planting instructions on a web page. That's the `A2` finding,
and it escalates to **CRITICAL** when all three are present.
"""

MODEL_BLURB = """
### 🔒 Airlock — scan the parts

Upload a model artifact. Airlock disassembles pickle opcodes and reads format headers to
find code-execution payloads, `trust_remote_code`, archive smuggling, and provenance gaps.

**It never unpickles, imports, or executes anything** — which is exactly why it's safe to
point at a file you don't trust. That's also why this public Space can accept your upload
at all. Supported: `.pkl` `.bin` `.pt` `.pth` `.ckpt` `.safetensors` `.onnx` `.h5` `.npy`,
including gzip/zlib-compressed and zip-nested variants.
"""

with gr.Blocks(title="Bulwark — AI agent supply-chain security", theme=gr.themes.Soft()) as demo:
    gr.Markdown(INTRO)

    with gr.Tabs():
        # ------------------------------------------------------------------ #
        with gr.Tab("⚖️ Audit an agent"):
            gr.Markdown(AGENT_BLURB)
            with gr.Row():
                with gr.Column(scale=1):
                    config = gr.Code(
                        value=EXAMPLE_TRIFECTA,
                        language="yaml",
                        label="Agent config (YAML or JSON)",
                        lines=20,
                    )
                    with gr.Row():
                        audit_btn = gr.Button("Audit", variant="primary")
                        rec_btn = gr.Button("Harden it")
                    gr.Markdown("**Examples**")
                    with gr.Row():
                        gr.Button("Lethal trifecta", size="sm").click(
                            lambda: EXAMPLE_TRIFECTA, outputs=config
                        )
                        gr.Button("Over-privileged", size="sm").click(
                            lambda: EXAMPLE_DEVOPS, outputs=config
                        )
                    with gr.Row():
                        gr.Button("OpenAI Assistant", size="sm").click(
                            lambda: EXAMPLE_ASSISTANT, outputs=config
                        )
                        gr.Button("Least-privilege", size="sm").click(
                            lambda: EXAMPLE_CLEAN, outputs=config
                        )
                with gr.Column(scale=1):
                    agent_out = gr.Markdown(label="Result")

            audit_btn.click(audit_agent, inputs=config, outputs=agent_out)
            rec_btn.click(recommend_agent, inputs=config, outputs=agent_out)

        # ------------------------------------------------------------------ #
        with gr.Tab("🔒 Scan a model"):
            gr.Markdown(MODEL_BLURB)
            with gr.Row():
                with gr.Column(scale=1):
                    upload = gr.File(label="Model artifact", type="filepath")
                    scan_btn = gr.Button("Scan", variant="primary")
                with gr.Column(scale=1):
                    model_out = gr.Markdown(label="Result")

            scan_btn.click(scan_model, inputs=upload, outputs=model_out)

    gr.Markdown(
        "---\n"
        "Bulwark is a **defensive** security project: it detects and reports risk, and never "
        "weaponizes. Every fixture and example here is benign and inert. "
        "Apache-2.0 · [source](https://github.com/mk12002/Bulwark)"
    )

if __name__ == "__main__":
    demo.launch()
