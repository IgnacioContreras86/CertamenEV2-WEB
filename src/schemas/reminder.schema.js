import { object, string, boolean, optional } from 'valibot';

export const createReminderSchema = object({
  content: string(),
  important: optional(boolean())
});

export const updateReminderSchema = object({
  content: optional(string()),
  important: optional(boolean())
}); 