import { NextResponse } from "next/server";

export async function GET() {
  const endpoints = [
    "http://127.0.0.1:11434/api/tags",
    "http://localhost:11434/api/tags",
  ];

  for (const url of endpoints) {
    try {
      const res = await fetch(url, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        return NextResponse.json({
          status: "online",
          models: data.models?.map((m: any) => m.name) || [],
        });
      }
    } catch {
      // try fallback endpoint
    }
  }

  return NextResponse.json(
    {
      status: "offline",
      error: "Ollama not reachable",
    },
    { status: 503 }
  );
}