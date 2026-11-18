import { GoogleGenAI, Type } from '@google/genai';

export interface AiThreatAssessment {
  available: boolean;
  model: string | null;
  summary: string | null;
  reasoningSteps: string[];
  error: string | null;
}

function getConfiguredGeminiKey(): string | null {
  const key = process.env.GEMINI_API_KEY?.trim();
  if (!key || key === 'MY_GEMINI_API_KEY' || key.startsWith('CHANGE_ME')) {
    return null;
  }
  return key;
}

export async function generateAiThreatExplanation(context: {
  scanType: 'url' | 'email' | 'domain';
  indicator: string;
  riskScore: number;
  riskLevel: string;
  threatCategory: string;
  findings: string[];
}): Promise<AiThreatAssessment> {
  const apiKey = getConfiguredGeminiKey();
  if (!apiKey) {
    return {
      available: false,
      model: null,
      summary: null,
      reasoningSteps: [],
      error: 'Gemini AI explainability unavailable: GEMINI_API_KEY is not configured in server secrets.',
    };
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const prompt = [
      `Analyze this defensive SOC telemetry for a ${context.scanType.toUpperCase()} indicator.`,
      `Indicator: ${context.indicator.slice(0, 320)}`,
      `Computed Risk Score: ${context.riskScore}/100 (${context.riskLevel})`,
      `Category: ${context.threatCategory}`,
      `Observed Signals:\n- ${context.findings.slice(0, 10).join('\n- ')}`,
      'Provide a concise, objective SOC analyst summary (2-3 sentences) and 3-4 concrete defensive verification steps. Never claim certainty beyond observed evidence.',
    ].join('\n\n');

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: prompt,
      config: {
        systemInstruction:
          'You are a Principal SOC Threat Intelligence Analyst writing concise, evidence-grounded defensive assessments. Never fabricate unverified facts or overstate certainty.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: {
              type: Type.STRING,
              description: 'Concise 2-3 sentence objective threat assessment grounded in the observed signals.',
            },
            reasoningSteps: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '3 to 4 concise analyst reasoning and triage steps.',
            },
          },
          required: ['summary', 'reasoningSteps'],
        },
      },
    });

    const raw = (response.text ?? '').trim();
    const parsed = JSON.parse(raw) as { summary?: string; reasoningSteps?: string[] };
    return {
      available: true,
      model: 'gemini-4-hydrogen',
      summary: parsed.summary ?? null,
      reasoningSteps: Array.isArray(parsed.reasoningSteps) ? parsed.reasoningSteps.slice(0, 5) : [],
      error: null,
    };
  } catch (err) {
    return {
      available: false,
      model: 'gemini-4-hydrogen',
      summary: null,
      reasoningSteps: [],
      error: err instanceof Error ? `Gemini explanation failed: ${err.message}` : 'Gemini explanation unavailable.',
    };
  }
}
