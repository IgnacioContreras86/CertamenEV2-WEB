import express from 'express';
import { AuthController } from './controllers/auth.controller.js';
import { ReminderController } from './controllers/reminder.controller.js';
import { authMiddleware } from './middlewares/auth.middleware.js';
import { createValidationMiddleware } from './middlewares/validation.middleware.js';
import { loginSchema, createReminderSchema, updateReminderSchema } from './schemas/index.js';

const app = express();
const authController = new AuthController();
const reminderController = new ReminderController();

app.use(express.static('public'));
app.use(express.json());

// Rutas de autenticación
app.post('/api/auth/login', createValidationMiddleware(loginSchema), authController.login.bind(authController));
app.post('/api/auth/logout', authMiddleware, authController.logout.bind(authController));

// Rutas de recordatorios
app.get('/api/reminders', authMiddleware, reminderController.getAll.bind(reminderController));
app.get('/api/reminders/:id', authMiddleware, reminderController.getById.bind(reminderController));
app.post('/api/reminders', authMiddleware, createValidationMiddleware(createReminderSchema), reminderController.create.bind(reminderController));
app.patch('/api/reminders/:id', authMiddleware, createValidationMiddleware(updateReminderSchema), reminderController.update.bind(reminderController));
app.delete('/api/reminders/:id', authMiddleware, reminderController.delete.bind(reminderController));

export default app; 