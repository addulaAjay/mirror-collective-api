export interface IQuizAnswersRepository {
  saveQuiz(quizData: any): Promise<string>;
}