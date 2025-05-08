import { ReminderRepository } from '../repositories/reminder.repository.js';

const reminderRepository = new ReminderRepository();

export class ReminderController {
  async getAll(req, res) {
    const reminders = await reminderRepository.findAll(req.user.id);
    res.json(reminders);
  }

  async getById(req, res) {
    const { id } = req.params;
    const reminder = await reminderRepository.findById(id, req.user.id);

    if (!reminder) {
      return res.status(404).json({
        error: "Recordatorio no encontrado"
      });
    }

    res.json(reminder);
  }

  async create(req, res) {
    const { content, important } = req.body;

    if (content.trim() === "" || content.length > 120) {
      return res.status(400).json({
        error: "El contenido debe ser un string no vacío de máximo 120 caracteres"
      });
    }

    const reminder = await reminderRepository.create({
      content: content.trim(),
      important: important ?? false
    }, req.user.id);

    res.status(201).json(reminder);
  }

  async update(req, res) {
    const { id } = req.params;
    const { content, important } = req.body;

    if (content !== undefined) {
      if (content.trim() === "" || content.length > 120) {
        return res.status(400).json({
          error: "El contenido debe ser un string no vacío de máximo 120 caracteres"
        });
      }
    }

    try {
      const reminder = await reminderRepository.update(id, {
        content: content?.trim(),
        important
      }, req.user.id);

      res.json(reminder);
    } catch (error) {
      res.status(404).json({
        error: "Recordatorio no encontrado"
      });
    }
  }

  async delete(req, res) {
    const { id } = req.params;

    try {
      await reminderRepository.delete(id, req.user.id);
      res.status(204).end();
    } catch (error) {
      res.status(404).json({
        error: "Recordatorio no encontrado"
      });
    }
  }
} 