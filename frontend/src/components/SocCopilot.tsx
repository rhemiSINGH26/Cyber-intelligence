import { useState, useRef, useEffect, type FormEvent } from "react";
import ReactMarkdown from "react-markdown";
import {
  Bot,
  Send,
  X,
  Sparkles,
  Trash2,
  Maximize2,
  Minimize2,
  ArrowRight,
  Loader2,
  Copy,
  Check,
  ShieldAlert,
} from "lucide-react";
import { askCopilot, type ChatMessage } from "@/api";
import { cn } from "@/lib/utils";

interface SocCopilotProps {
  isOpen?: boolean;
  onClose?: () => void;
  incidentId?: string;
}

const DEFAULT_QUESTIONS = [
  "Summarize all detected attacks in the SOC",
  "Explain the attack chain progression for INC-001",
  "What containment actions should I execute immediately?",
  "Which hosts and IPs are involved in lateral movement?",
];

export function SocCopilot({ isOpen: externalOpen, onClose: externalClose, incidentId }: SocCopilotProps) {
  const [internalOpen, setInternalOpen] = useState(false);
  const isControlled = externalOpen !== undefined;
  const open = isControlled ? externalOpen : internalOpen;
  const setOpen = (val: boolean) => {
    if (isControlled) {
      if (!val && externalClose) externalClose();
    } else {
      setInternalOpen(val);
    }
  };

  const [expanded, setExpanded] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "**Hello Analyst!** I am your **ThreatLens SOC Copilot**, powered by **Groq LLM**.\n\nI have real-time access to all detected attack chains, reconstructed kill-chain stages, compromised entities, and telemetry logs. How can I assist your investigation today?",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    if (open) {
      scrollToBottom();
    }
  }, [messages, open]);

  const handleSend = async (queryText?: string) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg: ChatMessage = { role: "user", content: textToSend.trim() };
    const newHistory = [...messages, userMsg];
    setMessages(newHistory);
    if (!queryText) setInput("");
    setLoading(true);

    try {
      const res = await askCopilot(textToSend.trim(), incidentId, newHistory);
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: res.answer,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Sorry, I encountered an issue querying the attack telemetry. Please try again.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([
      {
        role: "assistant",
        content: "Chat cleared. Ask me any question about the detected attacks, MITRE tactics, or forensic evidence.",
      },
    ]);
  };

  const copyMessage = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  return (
    <>
      {/* Floating Copilot Launcher Pill (Always available at bottom-right) */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="fixed bottom-6 right-6 z-40 flex items-center gap-2.5 rounded-full border border-primary/50 bg-card/95 px-4 py-2.5 shadow-2xl backdrop-blur-md transition-all duration-300 hover:scale-105 hover:border-primary hover:shadow-primary/25 group"
          title="Open Groq AI SOC Copilot"
        >
          <div className="relative grid size-7 place-items-center rounded-full bg-gradient-to-tr from-cyan-500 to-primary text-white shadow-md">
            <Sparkles className="size-4 animate-spin-slow" />
            <span className="absolute -top-0.5 -right-0.5 size-2 rounded-full bg-low animate-ping" />
          </div>
          <div className="text-left">
            <div className="text-xs font-bold text-foreground group-hover:text-primary transition-colors flex items-center gap-1.5">
              Ask SOC Copilot
              <span className="text-[9px] font-mono uppercase px-1.5 py-0.2 rounded bg-primary/20 text-primary border border-primary/30">
                Groq AI
              </span>
            </div>
            <div className="text-[10px] text-muted-foreground">Ask questions about detected attacks</div>
          </div>
        </button>
      )}

      {/* Copilot Chat Window */}
      {open && (
        <div
          className={cn(
            "fixed z-50 flex flex-col rounded-2xl border border-primary/40 bg-card/95 shadow-2xl backdrop-blur-2xl transition-all duration-300",
            expanded
              ? "inset-4 sm:inset-10"
              : "bottom-4 right-4 w-[92vw] sm:w-[490px] h-[640px] max-h-[88vh]"
          )}
        >
          {/* Header */}
          <header className="flex h-14 items-center justify-between border-b border-border px-4 bg-surface/50 rounded-t-2xl">
            <div className="flex items-center gap-2.5">
              <div className="grid size-8 place-items-center rounded-xl bg-gradient-to-br from-primary via-indigo-600 to-cyan-500 text-white shadow-md shadow-primary/20">
                <Bot className="size-4.5" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <h3 className="text-xs font-bold text-foreground">ThreatLens Copilot</h3>
                  <span className="rounded bg-primary/15 px-1.5 py-0.5 text-[9px] font-mono font-bold text-primary border border-primary/30">
                    Groq Qwen 2.5
                  </span>
                </div>
                <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                  <span className="size-1.5 rounded-full bg-low animate-pulse" /> Real-time attack intelligence
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={clearChat}
                className="grid size-7 place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                title="Clear conversation"
              >
                <Trash2 className="size-3.5" />
              </button>
              <button
                onClick={() => setExpanded(!expanded)}
                className="grid size-7 place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground transition-colors hidden sm:grid"
                title={expanded ? "Restore size" : "Expand window"}
              >
                {expanded ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
              </button>
              <button
                onClick={() => setOpen(false)}
                className="grid size-7 place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                title="Close Copilot"
              >
                <X className="size-4" />
              </button>
            </div>
          </header>

          {/* Messages Feed */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
            {messages.map((m, idx) => {
              const isUser = m.role === "user";
              return (
                <div
                  key={idx}
                  className={cn("flex gap-2.5 text-xs group", isUser ? "justify-end" : "justify-start")}
                >
                  {!isUser && (
                    <div className="grid size-6 shrink-0 place-items-center rounded-lg bg-primary/20 text-primary border border-primary/30 self-start mt-1">
                      <Bot className="size-3.5" />
                    </div>
                  )}

                  <div
                    className={cn(
                      "relative max-w-[88%] rounded-2xl p-3.5 leading-relaxed",
                      isUser
                        ? "bg-primary text-primary-foreground font-medium rounded-tr-none shadow-md"
                        : "bg-surface/90 border border-border text-foreground rounded-tl-none shadow-sm"
                    )}
                  >
                    {!isUser && (
                      <button
                        onClick={() => copyMessage(m.content, idx)}
                        className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-card text-muted-foreground hover:text-foreground transition-all"
                        title="Copy to clipboard"
                      >
                        {copiedIdx === idx ? <Check className="size-3 text-low" /> : <Copy className="size-3" />}
                      </button>
                    )}

                    {isUser ? (
                      <div className="whitespace-pre-wrap">{m.content}</div>
                    ) : (
                      <div className="prose prose-invert prose-xs max-w-none space-y-2">
                        <ReactMarkdown
                          components={{
                            h1: ({ children }) => (
                              <h1 className="text-sm font-bold text-primary mt-2 mb-1 border-b border-border/60 pb-1 flex items-center gap-1.5">
                                {children}
                              </h1>
                            ),
                            h2: ({ children }) => (
                              <h2 className="text-xs font-bold text-foreground mt-2 mb-1 border-b border-border/40 pb-0.5 flex items-center gap-1.5">
                                {children}
                              </h2>
                            ),
                            h3: ({ children }) => (
                              <h3 className="text-xs font-semibold text-primary mt-2 mb-0.5">
                                {children}
                              </h3>
                            ),
                            p: ({ children }) => (
                              <p className="my-1.5 leading-relaxed text-foreground/90">{children}</p>
                            ),
                            ul: ({ children }) => (
                              <ul className="my-1.5 space-y-1 pl-4 list-disc marker:text-primary/70">{children}</ul>
                            ),
                            ol: ({ children }) => (
                              <ol className="my-1.5 space-y-1 pl-4 list-decimal marker:text-primary/70">{children}</ol>
                            ),
                            li: ({ children }) => (
                              <li className="leading-snug">{children}</li>
                            ),
                            strong: ({ children }) => (
                              <strong className="font-semibold text-foreground text-[11.5px]">{children}</strong>
                            ),
                            code: ({ children }) => (
                              <code className="rounded border border-primary/30 bg-background/80 px-1.5 py-0.5 font-mono text-[11px] text-primary font-medium">
                                {children}
                              </code>
                            ),
                            pre: ({ children }) => (
                              <pre className="my-2 rounded-lg border border-border bg-background p-2.5 font-mono text-[11px] overflow-x-auto text-primary">
                                {children}
                              </pre>
                            ),
                            hr: () => <hr className="my-2.5 border-border/60" />,
                          }}
                        >
                          {m.content}
                        </ReactMarkdown>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {/* Loading Indicator */}
            {loading && (
              <div className="flex items-center gap-2.5 text-xs text-muted-foreground">
                <div className="grid size-6 shrink-0 place-items-center rounded-lg bg-primary/20 text-primary border border-primary/30">
                  <Loader2 className="size-3.5 animate-spin" />
                </div>
                <div className="rounded-2xl rounded-tl-none bg-surface border border-border p-3 text-xs text-muted-foreground flex items-center gap-2">
                  <span className="size-2 rounded-full bg-primary animate-pulse" />
                  Reasoning over active SOC telemetry with Groq Qwen...
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Prompt Suggestions */}
          {messages.length <= 2 && (
            <div className="px-4 pb-2">
              <div className="text-[10px] uppercase font-mono tracking-wider text-muted-foreground mb-1.5 flex items-center gap-1">
                <Sparkles className="size-3 text-primary" /> Suggested Questions
              </div>
              <div className="grid grid-cols-1 gap-1.5">
                {DEFAULT_QUESTIONS.map((q, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSend(q)}
                    className="flex items-center justify-between text-left rounded-lg border border-border/80 bg-surface/60 px-2.5 py-1.5 text-[11px] text-muted-foreground hover:border-primary/50 hover:bg-surface hover:text-foreground transition-all group"
                  >
                    <span className="truncate">{q}</span>
                    <ArrowRight className="size-3 opacity-0 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all text-primary shrink-0 ml-1" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Chat Input */}
          <footer className="p-3 border-t border-border bg-surface/40 rounded-b-2xl">
            <form
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                handleSend();
              }}
              className="relative flex items-center"
            >
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about detected attacks, MITRE techniques, remediation..."
                disabled={loading}
                className="h-10 w-full rounded-xl border border-border bg-background pl-3 pr-10 text-xs outline-none placeholder:text-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all shadow-inner"
              />
              <button
                type="submit"
                disabled={!input.trim() || loading}
                className={cn(
                  "absolute right-1.5 grid size-7 place-items-center rounded-lg transition-colors",
                  input.trim() && !loading
                    ? "bg-primary text-primary-foreground shadow-sm hover:opacity-90"
                    : "text-muted-foreground hover:text-foreground"
                )}
                title="Send query"
              >
                <Send className="size-3.5" />
              </button>
            </form>
            <div className="mt-1 text-center text-[10px] text-muted-foreground/60">
              Powered by Groq Cloud API · High-speed inference on Qwen 2.5 27B
            </div>
          </footer>
        </div>
      )}
    </>
  );
}
