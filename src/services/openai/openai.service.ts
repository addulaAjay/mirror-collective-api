import { OpenAI } from 'openai';
import { loadConfig } from '../../infrastructure/config';
import { ChatMessage, IMirrorChatRepository } from '@/domain/repositories/mirror-chat.repository';

export class OpenAIService implements IMirrorChatRepository {
  private client: OpenAI;

  constructor() {
    const { openAiApiKey } = loadConfig();
    this.client = new OpenAI({ apiKey: openAiApiKey });
  }

  async send(messages: ChatMessage[]): Promise<string> {
    const resp = await this.client.chat.completions.create({
      model:       'gpt-4o',
      messages,
      temperature: 0.7,
      max_tokens:  1000,
    });
    return resp.choices[0]?.message?.content ?? '';
  }
}
