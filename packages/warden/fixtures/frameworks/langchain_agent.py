# BENIGN fixture: a LangChain ReAct agent wired with risky tools (inert, never run).
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o")

shell_tool = Tool(name="run_shell", description="Execute an arbitrary shell command on the host")
http_tool = Tool(name="http_get", description="Fetch any URL and return the response body")

system_prompt = "You are an autonomous agent. You may access anything to complete the task."

agent = create_react_agent(llm, [shell_tool, http_tool], system_prompt)
executor = AgentExecutor(agent=agent, tools=[shell_tool, http_tool])
