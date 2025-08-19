import { IQuizAnswersRepository } from '../repositories';

export interface QuizAnswerData {
    userId: string;
    answers: Array<{
        questionId: string;
        selectedAnswers: string[];
    }>;
    completedAt: Date;
    totalQuestions: number;
}

export interface SaveQuizAnswersRequest {
    userId: string;
    answers: Array<{
        questionId: string;
        selectedAnswers: string[];
    }>;
}

export interface QuizAnswersResponse {
    id: string;
    quizId: string;
    userId: string;
    totalQuestions: number;
    completedAt: Date;
}

export class QuizAnswersUseCase {
    constructor(private readonly quizAnswerRepository: IQuizAnswersRepository) {}

    async execute(request: SaveQuizAnswersRequest): Promise<string> {
        const quizAnswerData: QuizAnswerData = {
            userId: request.userId,
            answers: request.answers.map((answer: { questionId: string; selectedAnswers: string[] }) => ({
                ...answer
            })),
            completedAt: new Date(),
            totalQuestions: request.answers.length
        };
        
        const savedQuizAnswer = await this.quizAnswerRepository.saveQuiz(quizAnswerData);
        return savedQuizAnswer;
    }
}