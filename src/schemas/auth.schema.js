import { object, string } from 'valibot';

export const loginSchema = object({
  username: string(),
  password: string()
}); 