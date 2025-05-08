import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export class ReminderRepository {
  async findAll(userId) {
    return prisma.reminder.findMany({
      where: { userId },
      orderBy: [
        { important: 'desc' },
        { createdAt: 'asc' }
      ]
    });
  }

  async findById(id, userId) {
    return prisma.reminder.findFirst({
      where: { id, userId }
    });
  }

  async create(data, userId) {
    return prisma.reminder.create({
      data: {
        ...data,
        userId
      }
    });
  }

  async update(id, data, userId) {
    return prisma.reminder.update({
      where: { id, userId },
      data
    });
  }

  async delete(id, userId) {
    return prisma.reminder.delete({
      where: { id, userId }
    });
  }
} 