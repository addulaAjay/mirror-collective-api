// src/services/openai/OpenAIService.spec.ts

import { beforeEach, describe, expect, test, vi } from 'vitest';
import type { ChatMessage } from '../../domain/repositories/mirror-chat.repository';

// 1) Mock the OpenAI SDK before importing your service
vi.mock('openai', () => {
  return {
    OpenAI: class {
      // `chat` is assigned on each instance
      public chat = {
        completions: {
          create: vi.fn(),
        },
      };
    },
  };
});

// 2) Mock loadConfig to supply a dummy API key
vi.mock('../../infrastructure/config', () => ({
  loadConfig: () => ({ openAiApiKey: 'test-openai-key-xxxxxxxxxxxxxxxxxxxx' }),
}));

import { OpenAIService } from './openai.service';

describe('OpenAIService', () => {
  let service: OpenAIService;
  let mockCreate: ReturnType<typeof vi.fn>;
  const sampleMessages: ChatMessage[] = [
    { role: 'system',  content: 'sys' },
    { role: 'user',    content: 'hello' },
  ];

  beforeEach(() => {
    service = new OpenAIService();
    // Ensure the client is initialized and matches the mock structure
    // @ts-ignore - we know `client` is there
    if (!(service as any).client?.chat?.completions?.create) {
      // Assign the mock manually if not present (for test reliability)
      (service as any).client = {
        chat: {
          completions: {
            create: vi.fn(),
          },
        },
      };
    }
    mockCreate = (service as any).client.chat.completions.create;
    mockCreate.mockReset();
  });

  test('returns the content on success', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [{ message: { content: 'gpt reply' } }],
    });

    const reply = await service.send(sampleMessages);
    expect(reply).toBe('gpt reply');
    expect(mockCreate).toHaveBeenCalledWith({
      model:       'gpt-4o',
      messages:    sampleMessages,
      temperature: 0.7,
      max_tokens:  1000,
    });
  });

  test('falls back to empty string if content is missing', async () => {
    mockCreate.mockResolvedValueOnce({ choices: [{}] });
    const reply = await service.send(sampleMessages);
    expect(reply).toBe('');
  });

  test('propagates errors from the SDK', async () => {
    mockCreate.mockRejectedValueOnce(new Error('network failure'));
    await expect(service.send(sampleMessages)).rejects.toThrow('network failure');
  });
});
