import { ChatMessage, IMirrorChatRepository,  } from '../repositories/mirror-chat.repository';


export interface MirrorChatRequest {
  message: string;
  conversationHistory?: ChatMessage[];
}

export interface MirrorChatResponse {
  reply: string;
  timestamp: string;
}

export class MirrorChatUseCase {
  constructor(private chatService: IMirrorChatRepository) {}

  async execute(request: MirrorChatRequest): Promise<MirrorChatResponse> {
    // build the prompt array
    const systemPrompt: ChatMessage = {
      role:    'system',
      content: 'You are a sentiment analysis expert. Analyze the sentiment of the text and provide a rating from 1 to 5 stars and a confidence score between 0 and 1.',
    };

    const messages: ChatMessage[] = [
      systemPrompt,
      ...(request.conversationHistory ?? []),
      { role: 'user', content: request.message },
    ];

    // call the injected service
    const reply = await this.chatService.send(messages);

    // return the exact shape your controller expects
    return {
      reply,
      timestamp: new Date().toISOString(),
    };
  }
}
