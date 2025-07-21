export type ChatMessage = {
  role: 'system' | 'user' | 'assistant';
  content: string;
};

export interface IMirrorChatRepository {
  send(messages: ChatMessage[]): Promise<string>;
}
